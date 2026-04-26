"""
Direct WinAPI interface enumeration via iphlpapi.GetAdaptersAddresses.

Why: netifaces on Windows historically misses some interfaces (IPv6 on
XP, virtual adapters with non-ASCII names) and on XP we additionally
shell out to `wmic` / `netsh` to fill the gaps.  WMIC is itself buggy
on XP -- it holds an exclusive file lock that breaks under concurrency,
and slow shells cost startup time.

Bypass all of that with one ctypes call to iphlpapi.GetAdaptersAddresses
(exported on every Windows version from XP SP1 through 11).  The same
structure layout works across Win versions; this module walks the
returned linked-list of IP_ADAPTER_ADDRESSES and produces a
netifaces-compatible dict the rest of the codebase can consume.

Usage:

    from aionetiface.utility.win_iphlpapi import (
        is_supported, get_interfaces,
    )

    if is_supported():
        # Returns {if_name: {AF_INET: [...], AF_INET6: [...],
        #                    AF_LINK: [{"addr": mac}], "name": friendly}}
        nifaces = get_interfaces()

This module is import-safe on non-Windows: is_supported() returns False
and the rest of the entry points raise RuntimeError if you call them
anyway.  No top-level ctypes calls so the module loads cleanly under
unit-test runs on Linux/Mac.
"""

from typing import Any, Dict, List, Optional
import ctypes
import socket
import sys

if sys.platform == "win32":
    from ctypes import wintypes


# Constants from iphlpapi.h / ws2def.h.
AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23

# GetAdaptersAddresses Flags param. We ask for "everything we need" and
# "skip stuff we don't" -- the skip flags shave milliseconds on hosts
# with lots of adapters.
GAA_FLAG_INCLUDE_PREFIX = 0x0010
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_SKIP_FRIENDLY_NAME = 0x0020  # XP-only; ignored on Vista+

# Win32 error codes used by GetAdaptersAddresses.
ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232
ERROR_NOT_ENOUGH_MEMORY = 8


def is_supported() -> bool:
    """True iff this process can call iphlpapi.GetAdaptersAddresses.

    Cheap top-level check so callers don't have to import-guard every
    entry point. False on non-Windows and on Windows builds where
    iphlpapi.dll happens to be missing (very rare).
    """
    if sys.platform != "win32":
        return False
    try:
        ctypes.windll.iphlpapi  # pylint: disable=pointless-statement
        return True
    except (AttributeError, OSError):
        return False


# ---------------------------------------------------------------------------
# Structure layouts. Built from MSDN's IP_ADAPTER_ADDRESSES_LH definition;
# the "_LH" tail (XP+) layout is what GetAdaptersAddresses returns on every
# version we care about.  We define the bits we read; trailing fields are
# left as opaque buffer.
# ---------------------------------------------------------------------------


if sys.platform == "win32":

    class SOCKADDR(ctypes.Structure):
        # Just enough header to discriminate AF; the actual address bytes
        # live at the same offsets across sockaddr_in / sockaddr_in6 so
        # we cast based on sa_family.
        _fields_ = [
            ("sa_family", wintypes.USHORT),
            ("sa_data", ctypes.c_ubyte * 14),
        ]

    class SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ("sin_family", wintypes.USHORT),
            ("sin_port", wintypes.USHORT),
            ("sin_addr", ctypes.c_ubyte * 4),
            ("sin_zero", ctypes.c_ubyte * 8),
        ]

    class SOCKADDR_IN6(ctypes.Structure):
        _fields_ = [
            ("sin6_family", wintypes.USHORT),
            ("sin6_port", wintypes.USHORT),
            ("sin6_flowinfo", wintypes.ULONG),
            ("sin6_addr", ctypes.c_ubyte * 16),
            ("sin6_scope_id", wintypes.ULONG),
        ]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [
            ("lpSockaddr", ctypes.POINTER(SOCKADDR)),
            ("iSockaddrLength", wintypes.INT),
        ]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", wintypes.UINT),
        ("SuffixOrigin", wintypes.UINT),
        ("DadState", wintypes.UINT),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("LeaseLifetime", wintypes.ULONG),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
    ]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    # MAX_ADAPTER_ADDRESS_LENGTH = 8 in iphlpapi.h. We only read up to the
    # gateway field; trailing fields are left as ctypes.c_ubyte * 64 so
    # the structure size matches what the API returns regardless of OS.
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("FriendlyName", wintypes.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", wintypes.UINT),
        ("Ipv6IfIndex", wintypes.DWORD),
        ("ZoneIndices", wintypes.DWORD * 16),
        # Trailing fields (FirstPrefix, gateways, DHCP, etc.) we don't
        # use go in an opaque tail buffer. 512 bytes covers Win11 layout.
        ("Tail", ctypes.c_ubyte * 512),
    ]

    def get_adapters_addresses_proto():
        """ctypes prototype for GetAdaptersAddresses with explicit signature."""
        proto = ctypes.windll.iphlpapi.GetAdaptersAddresses
        proto.argtypes = [
            wintypes.ULONG,   # Family
            wintypes.ULONG,   # Flags
            ctypes.c_void_p,  # Reserved
            ctypes.POINTER(IP_ADAPTER_ADDRESSES),  # AdapterAddresses
            ctypes.POINTER(wintypes.ULONG),         # SizePointer
        ]
        proto.restype = wintypes.ULONG
        return proto


def sockaddr_to_ip(sock_addr: Any) -> Optional[str]:
    """Convert a SOCKET_ADDRESS containing a v4 or v6 sockaddr into a string IP.

    Returns None when the family isn't INET / INET6 (link-layer or
    other non-IP addresses appearing in PhysicalAddress fields are
    handled separately).
    """
    if not sock_addr.lpSockaddr:
        return None

    family = sock_addr.lpSockaddr.contents.sa_family
    if family == AF_INET:
        sin = ctypes.cast(sock_addr.lpSockaddr, ctypes.POINTER(SOCKADDR_IN)).contents
        return socket.inet_ntoa(bytes(sin.sin_addr))
    if family == AF_INET6:
        sin6 = ctypes.cast(sock_addr.lpSockaddr, ctypes.POINTER(SOCKADDR_IN6)).contents
        # XP doesn't have inet_ntop in the socket module; fall back to
        # manual hexing if needed.
        raw = bytes(sin6.sin6_addr)
        try:
            ip = socket.inet_ntop(socket.AF_INET6, raw)
        except (AttributeError, ValueError):
            ip = ":".join(
                "{0:x}{1:02x}".format(raw[i], raw[i + 1]).lstrip("0") or "0"
                for i in range(0, 16, 2)
            )
        scope = sin6.sin6_scope_id
        if scope:
            ip = "{0}%{1}".format(ip, scope)
        return ip
    return None


def mac_from_physical(buf: Any, length: int) -> str:
    """Format the first *length* bytes of an adapter's PhysicalAddress as a MAC."""
    if length <= 0:
        return ""
    return ":".join("{0:02x}".format(buf[i]) for i in range(min(length, 6)))


def get_interfaces() -> Dict[str, Dict[Any, Any]]:
    """Enumerate every adapter via GetAdaptersAddresses and return a
    netifaces-shape dict keyed by friendly name.

    Output layout per interface::

        {
            "<friendly name>": {
                "name": "<friendly name>",
                "description": "<adapter description>",
                "ifindex": <int>,
                "ipv6_ifindex": <int>,
                "mac": "aa:bb:cc:dd:ee:ff",
                socket.AF_INET: [{"addr": "1.2.3.4", "prefix": 24}, ...],
                socket.AF_INET6: [{"addr": "fe80::...%3", "prefix": 64}, ...],
            },
            ...
        }

    Empty AF lists are still keyed so callers can iterate without
    KeyError. Adapters with zero unicast addresses are still returned --
    callers that don't care can filter on len(d[AF_INET]) etc.

    Raises RuntimeError on non-Windows or when GetAdaptersAddresses
    refuses to allocate enough buffer (very rare; would indicate a
    badly broken Windows install).
    """
    if not is_supported():
        raise RuntimeError("GetAdaptersAddresses unavailable on this platform")

    proto = get_adapters_addresses_proto()
    flags = (
        GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
    )

    # Two-call pattern: first call with size=0 to learn the required
    # buffer length, then allocate and call again. iphlpapi may need
    # a few KB up to ~30KB on hosts with many virtual adapters.
    size = wintypes.ULONG(0)
    rc = proto(AF_UNSPEC, flags, None, None, ctypes.byref(size))
    if rc != ERROR_BUFFER_OVERFLOW and rc != 0:
        raise RuntimeError(
            "GetAdaptersAddresses sizing call failed rc={0}".format(rc)
        )
    if size.value == 0:
        return {}

    buf = (ctypes.c_ubyte * size.value)()
    head = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    rc = proto(AF_UNSPEC, flags, None, head, ctypes.byref(size))
    if rc == ERROR_NO_DATA:
        return {}
    if rc != 0:
        raise RuntimeError("GetAdaptersAddresses fetch failed rc={0}".format(rc))

    interfaces = {}
    cur = head
    while cur:
        adapter = cur.contents
        name = adapter.FriendlyName or adapter.Description or adapter.AdapterName
        if isinstance(name, bytes):
            try:
                name = name.decode("utf-8")
            except UnicodeDecodeError:
                name = name.decode("latin-1", errors="replace")
        if name is None:
            name = "<adapter {0}>".format(adapter.IfIndex)

        info = {
            "name": name,
            "description": adapter.Description or "",
            "ifindex": int(adapter.IfIndex),
            "ipv6_ifindex": int(adapter.Ipv6IfIndex),
            "mac": mac_from_physical(
                adapter.PhysicalAddress, int(adapter.PhysicalAddressLength)
            ),
            socket.AF_INET: [],
            socket.AF_INET6: [],
        }

        ucur = adapter.FirstUnicastAddress
        while ucur:
            entry = ucur.contents
            ip_str = sockaddr_to_ip(entry.Address)
            if ip_str is not None:
                family = entry.Address.lpSockaddr.contents.sa_family
                if family == AF_INET:
                    info[socket.AF_INET].append(
                        {"addr": ip_str, "prefix": int(entry.OnLinkPrefixLength)}
                    )
                elif family == AF_INET6:
                    info[socket.AF_INET6].append(
                        {"addr": ip_str, "prefix": int(entry.OnLinkPrefixLength)}
                    )
            ucur = entry.Next

        # Drop adapters with no friendly name AND no IPs -- they show
        # up as ghost entries on some Windows installs and confuse
        # downstream selectors.
        if name or info[socket.AF_INET] or info[socket.AF_INET6]:
            interfaces[name] = info

        if not adapter.Next:
            break
        cur = adapter.Next

    return interfaces


def to_netifaces_shape(interfaces: Dict[str, Dict[Any, Any]]) -> Dict[str, Dict[int, List[Dict[str, Any]]]]:
    """Project our richer shape into the exact dict layout that
    netifaces' ifaddresses(name) returns, so callers can drop this
    module in as a fallback without rewriting their parsing.

    netifaces shape::

        {AF_INET: [{"addr", "netmask", "broadcast"}, ...],
         AF_INET6: [{"addr", "netmask"}, ...],
         AF_LINK:  [{"addr": "aa:bb:..."}]}

    We don't compute netmask from prefix here (netifaces returns it
    as a dotted-quad string) -- callers needing netmask can derive
    it from prefix or call the bind helpers that already accept
    prefix. This is a *minimum* compat shape.
    """
    AF_LINK = 17  # netifaces uses AF_LINK = 17 on Linux/Mac, varies on
                  # Windows; the constant value is what callers expect.
    out = {}
    for name, info in interfaces.items():
        per_iface = {AF_INET: [], AF_INET6: [], AF_LINK: []}
        for v4 in info[socket.AF_INET]:
            per_iface[AF_INET].append({"addr": v4["addr"]})
        for v6 in info[socket.AF_INET6]:
            per_iface[AF_INET6].append({"addr": v6["addr"]})
        if info["mac"]:
            per_iface[AF_LINK].append({"addr": info["mac"]})
        out[name] = per_iface
    return out
