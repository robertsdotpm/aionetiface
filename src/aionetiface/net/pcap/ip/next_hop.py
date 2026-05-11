"""Next-hop MAC resolution for the userspace pcap TCP stack.

When the pcap TCP plugin builds an outbound Ethernet frame, the destination
MAC must be the L2 next-hop -- which differs from the destination IP's
MAC whenever the destination is OFF the local subnet.  On a same-L2 path
(linux veth, two boxes on one switch) the L2 next-hop IS the peer, and the
inbound-frame MAC-learning in `tcp/conn.py:process_frame` is enough.

On a cross-NAT path the L2 next-hop is the local default gateway and the
peer's MAC is never seen on our wire, so MAC-learning never fires.  Falling
back to ETH_BROADCAST as the dst MAC of a unicast IPv4 frame causes most
home-router NATs to silently drop the egress, because:

    1. The gateway will not NAT/forward a frame whose L2 dst is broadcast.
    2. Some VMware / virtualbox vSwitches drop broadcast-dst unicast-payload
       frames as malformed.
    3. Windows XP's softswitch behaviour around the frame's CRC also varies.

This module reads the host's existing ARP cache and route table (no probes,
no ARP requests, no privileged calls) to learn the gateway MAC.  Everything
is purely read-only; it only ever uses `subprocess` to invoke `arp` and
parse the output, or reads `/proc/net/arp` and `/proc/net/route` directly.

API:
    resolve_next_hop_mac(dst_ip, local_ip=None, local_subnet=None)
        -> bytes (6) | None

The caller passes the destination IP and, optionally, the host's local IP
and the local subnet mask in dotted-quad form.  When local_subnet is
provided we can decide "same-LAN vs off-LAN" precisely; without it we fall
back to OS route lookup.

The helper returns the MAC of:
    - the dst_ip itself, if the dst is on the local subnet (and has an
      ARP entry)
    - else the default gateway

or None if neither could be found.

Platform branches:
    linux / android      -- /proc/net/arp + /proc/net/route
    windows (incl. XP)   -- `arp -a` + `route print`
    macos / *bsd         -- `arp -an` + `netstat -rn -f inet`

All parsing is defensive: any unparsable line is skipped, not raised.
"""
import os
import struct
import subprocess
import sys

from . import eth

try:
    from ....utility.fstr import fstr
except (ImportError, ValueError):
    # ValueError("attempted relative import beyond top-level package")
    # fires when this module is imported under a shallower package
    # context (e.g. test fixtures sym-linking ip/ in isolation).  The
    # shim is functionally identical for our use.
    def fstr(template, args):
        return template.format(*args)


def is_windows():
    return sys.platform.startswith("win")


def is_linux():
    return sys.platform.startswith("linux")


def is_darwin():
    return sys.platform.startswith("darwin")


def is_bsd():
    return (
        sys.platform.startswith("freebsd")
        or sys.platform.startswith("openbsd")
        or sys.platform.startswith("netbsd")
        or sys.platform.startswith("dragonfly")
        or "bsd" in sys.platform
    )


# --- IP / subnet helpers ---------------------------------------------------


def ip_to_int(addr):
    """Dotted-quad / 4-byte bytes -> 32-bit int.  Returns None on bad input."""
    if isinstance(addr, (bytes, bytearray)) and len(addr) == 4:
        return struct.unpack("!I", bytes(addr))[0]
    if not isinstance(addr, str):
        return None
    parts = addr.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    for o in octets:
        if o < 0 or o > 255:
            return None
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


def same_subnet(ip_a, ip_b, mask):
    """True iff ip_a and ip_b share the same prefix under mask.  Any arg
    can be dotted-quad or bytes.  Returns False on unparsable input."""
    a = ip_to_int(ip_a)
    b = ip_to_int(ip_b)
    m = ip_to_int(mask)
    if a is None or b is None or m is None:
        return False
    return (a & m) == (b & m)


# --- Subprocess helper -----------------------------------------------------


def run_text(cmd):
    """Run a system command, return decoded stdout or None on any failure.
    Cross-platform: uses subprocess with check=False and a short timeout
    so a hung helper never wedges the calling event loop."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except (OSError, ValueError):
        return None
    try:
        out, _ = proc.communicate(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        return None
    if out is None:
        return None
    try:
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None


def parse_mac_loose(text):
    """Parse a MAC in either colon ('aa:bb:..') or dash ('aa-bb-..') form,
    returning 6 bytes or None.  Used for OS-level ARP table output which
    differs by platform."""
    if not isinstance(text, str):
        return None
    t = text.strip().lower()
    if not t:
        return None
    sep = None
    if ":" in t:
        sep = ":"
    elif "-" in t:
        sep = "-"
    else:
        return None
    parts = t.split(sep)
    if len(parts) != 6:
        return None
    try:
        return bytes(bytearray(int(p, 16) for p in parts))
    except ValueError:
        return None


# --- Linux readers ---------------------------------------------------------


def linux_arp_table():
    """Return dict ip_str -> mac_bytes from /proc/net/arp.  Skips entries
    with all-zero MAC (kernel's "incomplete" entry)."""
    table = {}
    try:
        with open("/proc/net/arp", "r") as fh:
            lines = fh.readlines()
    except (OSError, IOError):
        return table
    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        ip_str = cols[0]
        mac_str = cols[3]
        mac = parse_mac_loose(mac_str)
        if mac is None:
            continue
        if mac == eth.MAC_ZERO:
            continue
        table[ip_str] = mac
    return table


def linux_default_gateway():
    """Return dotted-quad IP of the default IPv4 gateway from
    /proc/net/route, or None.  If multiple defaults exist, returns the
    one with the lowest metric."""
    try:
        with open("/proc/net/route", "r") as fh:
            lines = fh.readlines()
    except (OSError, IOError):
        return None
    best_gw = None
    best_metric = None
    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 8:
            continue
        # Columns: iface dest gw flags refcnt use metric mask ...
        dest_hex = cols[1]
        gw_hex = cols[2]
        try:
            metric = int(cols[6])
        except ValueError:
            continue
        if dest_hex != "00000000":
            continue
        # Gateway in /proc/net/route is little-endian hex.
        try:
            gw_int = int(gw_hex, 16)
        except ValueError:
            continue
        # Convert little-endian to dotted-quad.
        b0 = gw_int & 0xFF
        b1 = (gw_int >> 8) & 0xFF
        b2 = (gw_int >> 16) & 0xFF
        b3 = (gw_int >> 24) & 0xFF
        gw_str = "{0}.{1}.{2}.{3}".format(b0, b1, b2, b3)
        if best_metric is None or metric < best_metric:
            best_metric = metric
            best_gw = gw_str
    return best_gw


# --- Windows readers -------------------------------------------------------


def windows_arp_table():
    """Parse `arp -a` output into ip_str -> mac_bytes.  Works on XP through
    Windows 11 -- the output format has been stable since at least Win 2000.

    Example fragment:
        Interface: 10.0.1.132 --- 0x10004
          Internet Address      Physical Address      Type
          10.0.1.1              40-ed-00-63-d6-79     dynamic
    """
    text = run_text(["arp", "-a"])
    if not text:
        return {}
    table = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_str = parts[0]
        # First field must look like an IPv4 dotted-quad.
        if ip_to_int(ip_str) is None:
            continue
        mac = parse_mac_loose(parts[1])
        if mac is None:
            continue
        if mac == eth.MAC_ZERO:
            continue
        table[ip_str] = mac
    return table


def windows_default_gateway():
    """Parse `route print` output for the default IPv4 gateway.

    Example fragment from XP / Win7+:
        Active Routes:
        Network Destination        Netmask          Gateway       Interface  Metric
                  0.0.0.0          0.0.0.0         10.0.1.1      10.0.1.132    1
    """
    text = run_text(["route", "print", "-4"])
    if not text:
        # XP's `route print` doesn't accept -4 but emits IPv4 by default.
        text = run_text(["route", "print"])
    if not text:
        return None
    best_gw = None
    best_metric = None
    in_active = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "Active Routes" in line:
            in_active = True
            continue
        if "Persistent Routes" in line or "IPv6 Route Table" in line:
            in_active = False
            continue
        if not in_active:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0] != "0.0.0.0":
            continue
        # Defensive: every column needs to look like an IP except metric.
        netmask = parts[1]
        gw = parts[2]
        if netmask != "0.0.0.0":
            continue
        if ip_to_int(gw) is None:
            continue
        metric = None
        # Metric is the last whitespace-separated column on every Windows
        # version we test, but XP sometimes pads with extra whitespace.
        try:
            metric = int(parts[-1])
        except ValueError:
            metric = None
        if metric is None:
            if best_gw is None:
                best_gw = gw
            continue
        if best_metric is None or metric < best_metric:
            best_metric = metric
            best_gw = gw
    return best_gw


# --- macOS / BSD readers ---------------------------------------------------


def unix_arp_table():
    """Parse `arp -an` output (BSD / macOS).  Lines look like:
        ? (10.0.1.1) at 40:ed:00:63:d6:79 on en0 ifscope [ethernet]
    """
    text = run_text(["arp", "-an"])
    if not text:
        return {}
    table = {}
    for raw in text.splitlines():
        line = raw.strip()
        if "(" not in line or ")" not in line or " at " not in line:
            continue
        try:
            ip_start = line.index("(") + 1
            ip_end = line.index(")")
            ip_str = line[ip_start:ip_end]
        except ValueError:
            continue
        if ip_to_int(ip_str) is None:
            continue
        try:
            mac_field = line.split(" at ", 1)[1].split()[0]
        except IndexError:
            continue
        mac = parse_mac_loose(mac_field)
        if mac is None:
            continue
        if mac == eth.MAC_ZERO:
            continue
        table[ip_str] = mac
    return table


def unix_default_gateway():
    """Parse `netstat -rn -f inet` output for the default IPv4 gateway."""
    text = run_text(["netstat", "-rn", "-f", "inet"])
    if not text:
        text = run_text(["netstat", "-rn"])
    if not text:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] not in ("default", "0.0.0.0"):
            continue
        gw = parts[1]
        if ip_to_int(gw) is None:
            continue
        return gw
    return None


# --- Unified front door ----------------------------------------------------


def os_arp_table():
    """Return the host OS's view of the ARP table as ip_str -> mac_bytes."""
    if is_linux():
        return linux_arp_table()
    if is_windows():
        return windows_arp_table()
    if is_darwin() or is_bsd():
        return unix_arp_table()
    return {}


def os_default_gateway():
    """Return the host OS's default IPv4 gateway (dotted-quad) or None."""
    if is_linux():
        return linux_default_gateway()
    if is_windows():
        return windows_default_gateway()
    if is_darwin() or is_bsd():
        return unix_default_gateway()
    return None


def resolve_next_hop_mac(
    dst_ip, local_ip=None, local_subnet=None, arp_cache=None,
):
    """Return the L2 next-hop MAC for an outbound IPv4 frame.

    Lookup order:
      1. If dst_ip is in the supplied ArpCache (learned from inbound
         frames), use that -- works for the same-LAN case.
      2. If dst_ip is on the local subnet (per local_ip+local_subnet),
         try the host OS ARP table for dst_ip directly.
      3. Otherwise look up the host default gateway IP and resolve THAT
         via the OS ARP table.

    Returns 6 bytes or None.  None means "give up, caller can fall back
    to broadcast and hope".  No side effects, no probes.
    """
    # Step 1: app-level learned cache.
    if arp_cache is not None:
        cached = arp_cache.get(dst_ip)
        if cached is not None and cached != eth.MAC_BROADCAST and cached != eth.MAC_ZERO:
            return cached

    # Step 2: same-subnet shortcut.
    if local_ip is not None and local_subnet is not None:
        if same_subnet(dst_ip, local_ip, local_subnet):
            table = os_arp_table()
            mac = table.get(dst_ip)
            if mac is not None:
                if arp_cache is not None:
                    arp_cache.put(dst_ip, mac)
                return mac
            # Same subnet but no cache entry -- no point falling through
            # to gateway lookup, the gateway won't forward an on-link
            # packet.  Return None and let the caller broadcast / ARP-probe.
            return None

    # Step 3: off-subnet -- resolve gateway.
    gw = os_default_gateway()
    if gw is None:
        return None
    table = os_arp_table()
    mac = table.get(gw)
    if mac is None:
        return None
    if arp_cache is not None:
        # Cache the gateway under its OWN ip, not the destination ip --
        # other off-LAN destinations should hit the same gateway entry.
        arp_cache.put(gw, mac)
    return mac


# --- Local NIC MAC resolution ----------------------------------------------
#
# The pcap stack writes frames directly onto the wire without going through
# the kernel's L2 framing, so it must supply its own source MAC.  The kernel
# normally fills this in transparently when an application calls send() on a
# regular socket; userspace pcap injection bypasses that path.  Frames with
# src_mac=00:00:00:00:00:00 are silently dropped by:
#   - MAC-learning bridges / switches (the source slot won't be learned, so
#     replies have nowhere to return),
#   - egress filters on consumer routers,
#   - VMware vSwitches with promiscuous-mode restrictions,
# all without any error returned to the injecting process.  So we resolve
# the local NIC's MAC up-front and stash it on the Connection.
#
# We resolve by local IP rather than by interface name because the
# Connection constructor already takes local_ip and the caller may not
# know the OS-level interface name -- on Windows in particular the pcap
# device name (\Device\NPF_{GUID}) is unrelated to the friendly name
# `ipconfig` uses.


def linux_local_mac(local_ip):
    """Find the MAC of the NIC carrying local_ip on Linux.

    Strategy: enumerate /sys/class/net/, check each iface's
    /sys/class/net/<iface>/address.  Cross-reference against the iface's
    IPs which we read from getifaddrs-equivalent via /proc/net/fib_trie
    or, simpler, iterate `ip -o addr show` and parse.

    To keep this dependency-free, we walk /sys/class/net and run
    `ip -o -4 addr show dev <iface>` per candidate.  On boxes without
    iproute2 (older embedded), we fall back to `ifconfig`.
    """
    try:
        ifaces = os.listdir("/sys/class/net")
    except (OSError, IOError):
        ifaces = []
    for iface in ifaces:
        addr_path = "/sys/class/net/" + iface + "/address"
        try:
            with open(addr_path, "r") as fh:
                mac_str = fh.read().strip()
        except (OSError, IOError):
            continue
        # Check if this iface carries local_ip.  Try iproute2 first.
        text = run_text(["ip", "-o", "-4", "addr", "show", "dev", iface])
        if not text:
            text = run_text(["ifconfig", iface])
        if not text:
            continue
        if local_ip not in text:
            continue
        mac = parse_mac_loose(mac_str)
        if mac is not None and mac != eth.MAC_ZERO:
            return mac
    return None


def windows_local_mac(local_ip):
    """Find the MAC of the NIC carrying local_ip on Windows (incl. XP).

    Parses `ipconfig /all` output, which has been stable since Win 2000.
    Each adapter section has a 'Physical Address' line followed by one or
    more 'IP Address' / 'IPv4 Address' lines.  We pair them by section.

    Example fragment from XP:
        Ethernet adapter Local Area Connection:
              Connection-specific DNS Suffix  . :
              Physical Address. . . . . . . . . : 00-0C-29-AB-CD-EF
              Dhcp Enabled. . . . . . . . . . . : Yes
              ...
              IP Address. . . . . . . . . . . . : 10.0.1.132
              Subnet Mask . . . . . . . . . . . : 255.255.255.0
              ...
    """
    text = run_text(["ipconfig", "/all"])
    if not text:
        return None
    current_mac = None
    sections = []
    section_macs = []
    section_ips = []
    cur_ips = []
    cur_mac = None
    in_section = False
    for raw in text.splitlines():
        line = raw.rstrip()
        # Section header: a non-indented line ending with a colon.
        if line and not line.startswith(" ") and not line.startswith("\t") and line.endswith(":"):
            # Flush previous section.
            if in_section:
                section_macs.append(cur_mac)
                section_ips.append(cur_ips)
            cur_mac = None
            cur_ips = []
            in_section = True
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if "Physical Address" in stripped:
            # Value after ':'.
            if ":" in stripped:
                val = stripped.split(":", 1)[1].strip().strip(".").strip()
                mac = parse_mac_loose(val)
                if mac is not None:
                    cur_mac = mac
            continue
        # Match IPv4 lines.  XP uses 'IP Address', Vista+ uses 'IPv4 Address'.
        # The value can have a trailing '(Preferred)' annotation on Vista+.
        if ("IP Address" in stripped) or ("IPv4 Address" in stripped):
            if ":" in stripped:
                val = stripped.split(":", 1)[1].strip()
                # Take the first whitespace-separated token.
                token = val.split()[0] if val else ""
                # Strip trailing punctuation.
                token = token.strip("().,")
                if ip_to_int(token) is not None:
                    cur_ips.append(token)
            continue
    # Flush trailing section.
    if in_section:
        section_macs.append(cur_mac)
        section_ips.append(cur_ips)
    # Find a section that contains local_ip and has a MAC.
    for mac, ips in zip(section_macs, section_ips):
        if mac is None:
            continue
        if local_ip in ips:
            return mac
    return None


def unix_local_mac(local_ip):
    """Find the MAC of the NIC carrying local_ip on macOS / *BSD.

    Parses `ifconfig` output.  Each adapter block starts at column 0
    with the iface name + flags; indented lines underneath include
    'ether <MAC>' and 'inet <IP>'.
    """
    text = run_text(["ifconfig"])
    if not text:
        return None
    section_mac = None
    section_ips = []
    macs = []
    ip_lists = []
    started = False
    for raw in text.splitlines():
        if not raw:
            continue
        if not raw.startswith(" ") and not raw.startswith("\t"):
            # New section starts.
            if started:
                macs.append(section_mac)
                ip_lists.append(section_ips)
            section_mac = None
            section_ips = []
            started = True
            continue
        stripped = raw.strip()
        # ether aa:bb:cc:dd:ee:ff
        if stripped.startswith("ether ") or stripped.startswith("lladdr "):
            parts = stripped.split()
            if len(parts) >= 2:
                mac = parse_mac_loose(parts[1])
                if mac is not None:
                    section_mac = mac
            continue
        # inet 10.0.1.132 netmask ...
        if stripped.startswith("inet "):
            parts = stripped.split()
            if len(parts) >= 2 and ip_to_int(parts[1]) is not None:
                section_ips.append(parts[1])
            continue
    if started:
        macs.append(section_mac)
        ip_lists.append(section_ips)
    for mac, ips in zip(macs, ip_lists):
        if mac is None:
            continue
        if local_ip in ips:
            return mac
    return None


def resolve_local_mac(local_ip):
    """Return the MAC of the local NIC that owns `local_ip`, or None.

    Cross-platform.  Read-only (subprocess calls and /sys reads only,
    no probes, no interface mutation).  None means "give up, caller can
    fall back to MAC_ZERO and hope the L2 path tolerates it".
    """
    if local_ip is None:
        return None
    try:
        if is_linux():
            return linux_local_mac(local_ip)
        if is_windows():
            return windows_local_mac(local_ip)
        if is_darwin() or is_bsd():
            return unix_local_mac(local_ip)
    except Exception as exc:
        # Defensive: any helper failure must NOT prevent the Connection
        # from at least attempting to inject (with MAC_ZERO src_mac as
        # fallback).
        print(fstr(
            "pcap next_hop: resolve_local_mac error {0}", (exc,)))
        return None
    return None
