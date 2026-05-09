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

    from aionetiface.nic.netifaces.windows.win_iphlpapi import (
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


def is_supported():
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

    # ---------------------------------------------------------------------------
    # GetAdaptersInfo structs (Win98+ / iphlpapi.dll).
    # Older API than GetAdaptersAddresses; returns subnet masks as dotted-quad
    # strings.  Used as a fallback for XP where GetAdaptersAddresses leaves
    # OnLinkPrefixLength uninitialised.
    # ---------------------------------------------------------------------------

    ADAPTER_NAME_LEN = 260   # MAX_ADAPTER_NAME_LENGTH (256) + 4
    ADAPTER_DESC_LEN = 132   # MAX_ADAPTER_DESCRIPTION_LENGTH (128) + 4
    ADAPTER_ADDR_LEN = 8     # MAX_ADAPTER_ADDRESS_LENGTH

    class IP_ADDRESS_STRING(ctypes.Structure):
        _fields_ = [("String", ctypes.c_char * 16)]

    class IP_ADDR_STRING(ctypes.Structure):
        pass

    IP_ADDR_STRING._fields_ = [
        ("Next", ctypes.POINTER(IP_ADDR_STRING)),
        ("IpAddress", IP_ADDRESS_STRING),
        ("IpMask", IP_ADDRESS_STRING),
        ("Context", wintypes.DWORD),
    ]

    class IP_ADAPTER_INFO(ctypes.Structure):
        pass

    IP_ADAPTER_INFO._fields_ = [
        ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
        ("ComboIndex", wintypes.DWORD),
        ("AdapterName", ctypes.c_char * ADAPTER_NAME_LEN),
        ("Description", ctypes.c_char * ADAPTER_DESC_LEN),
        ("AddressLength", wintypes.UINT),
        ("Address", ctypes.c_ubyte * ADAPTER_ADDR_LEN),
        ("Index", wintypes.DWORD),
        ("Type", wintypes.UINT),
        ("DhcpEnabled", wintypes.UINT),
        ("CurrentIpAddress", ctypes.c_void_p),
        ("IpAddressList", IP_ADDR_STRING),
        ("GatewayList", IP_ADDR_STRING),
        ("DhcpServer", IP_ADDR_STRING),
        ("HaveWins", wintypes.BOOL),
        ("PrimaryWinsServer", IP_ADDR_STRING),
        ("SecondaryWinsServer", IP_ADDR_STRING),
        ("LeaseObtained", ctypes.c_long),
        ("LeaseExpires", ctypes.c_long),
    ]


def sockaddr_to_ip(sock_addr):
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


def mac_from_physical(buf, length):
    """Format the first *length* bytes of an adapter's PhysicalAddress as a MAC."""
    if length <= 0:
        return ""
    return ":".join("{0:02x}".format(buf[i]) for i in range(min(length, 6)))


def get_interfaces():
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

        # AdapterName is the curly-brace GUID -- carry it through so the
        # netifaces vector adapter below can use it as the by_guid_index key.
        adapter_name = adapter.AdapterName
        if isinstance(adapter_name, bytes):
            try:
                adapter_name = adapter_name.decode("ascii")
            except UnicodeDecodeError:
                adapter_name = adapter_name.decode("latin-1", errors="replace")
        if adapter_name is None:
            adapter_name = ""

        info = {
            "name": name,
            "description": adapter.Description or "",
            "guid": adapter_name,
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


def to_netifaces_shape(interfaces):
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


# ---------------------------------------------------------------------------
# Netifaces-shaped vector adapter.
#
# Netifaces.start() in win_netifaces walks a vectors list of async
# coroutines, each returning a list of if_info dicts in a specific
# shape. We expose if_infos_from_iphlpapi() here so it can be prepended
# to that list as the primary Windows path. When iphlpapi succeeds (every
# Windows version from XP SP1 onward), the WMIC + netsh + PowerShell
# fallbacks never run -- skipping their slow shell calls + XP's WMIC
# lock contention.
# ---------------------------------------------------------------------------


def cidr_to_netmask_v4(prefix):
    """Convert an IPv4 prefix length to dotted-quad netmask, matching netifaces."""
    if prefix <= 0:
        return "0.0.0.0"
    if prefix >= 32:
        return "255.255.255.255"
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return "{0}.{1}.{2}.{3}".format(
        (mask >> 24) & 0xFF, (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF, mask & 0xFF,
    )


def get_v4_masks_from_adapters_info():
    """Return {ip_str: netmask_str} from GetAdaptersInfo.

    GetAdaptersInfo (Win98+) stores subnet masks as dotted-quad strings and
    populates them correctly on all supported Windows versions, including XP
    where GetAdaptersAddresses leaves OnLinkPrefixLength uninitialised.

    Returns an empty dict on non-Windows or if the API call fails.
    """
    if sys.platform != "win32":
        return {}
    try:
        proto = ctypes.windll.iphlpapi.GetAdaptersInfo
        proto.argtypes = [
            ctypes.POINTER(IP_ADAPTER_INFO),
            ctypes.POINTER(wintypes.ULONG),
        ]
        proto.restype = wintypes.ULONG

        size = wintypes.ULONG(0)
        rc = proto(None, ctypes.byref(size))
        if rc not in (0, ERROR_BUFFER_OVERFLOW):
            return {}
        if size.value == 0:
            return {}

        buf = (ctypes.c_ubyte * size.value)()
        head = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
        rc = proto(head, ctypes.byref(size))
        if rc == ERROR_NO_DATA:
            return {}
        if rc != 0:
            return {}

        masks = {}
        cur = head
        while cur:
            adapter = cur.contents
            addr_cur = ctypes.pointer(adapter.IpAddressList)
            while addr_cur:
                entry = addr_cur.contents
                try:
                    ip_str = entry.IpAddress.String.decode("ascii").rstrip("\x00")
                    mask_str = entry.IpMask.String.decode("ascii").rstrip("\x00")
                    if ip_str and ip_str != "0.0.0.0":
                        masks[ip_str] = mask_str
                except (UnicodeDecodeError, AttributeError):
                    pass
                addr_cur = entry.Next
            if not adapter.Next:
                break
            cur = adapter.Next
        return masks
    except (AttributeError, OSError):
        return {}


async def if_infos_from_iphlpapi():
    """Translate get_interfaces() into the netifaces-vector if_info shape.

    Returns a list of dicts each containing::

        {
            "guid":     "<{xxxxxxxx-xxxx-...}>",
            "name":     "<friendly name>",
            "no":       <ifindex>,
            "mac":      "aa:bb:cc:dd:ee:ff",
            "addr":     {IP4: [{"addr","af","host_limit","netmask"}, ...],
                          IP6: [...]},
            "gws":      {IP4: None, IP6: None},
            "defaults": [],
        }

    Adapters with neither v4 nor v6 unicast addresses are filtered out
    -- the existing vectors do the same so callers can iterate over
    if_infos without guarding for empty AF lists.

    Gateways are not extracted from GetAdaptersAddresses here even
    though the API exposes them; downstream is_default() falls back to
    a sock-trick UDP probe when gws is empty, and that already works
    on every supported Windows version. Adding gateway parsing here
    means widening the IP_ADAPTER_ADDRESSES struct (FirstPrefix,
    FirstWinsServerAddress, FirstGatewayAddress) which we don't need
    for the immediate "interface enumeration" job.
    """
    if not is_supported():
        return []

    # Local imports so the module stays loadable on non-Windows even
    # if the host code happens to import this name.
    from ....net.net_defs import IP4, IP6
    from ....net.ip_range import IPRange
    from ....net.net_utils import af_bitlen
    from ....utility.utils import fstr, log, log_exception

    interfaces = get_interfaces()

    # On XP, GetAdaptersAddresses leaves OnLinkPrefixLength uninitialised so
    # sanitize_prefix falls back to /32.  GetAdaptersInfo (older API, Win98+)
    # stores subnet masks as dotted-quad strings and works correctly on XP.
    v4_masks = get_v4_masks_from_adapters_info()

    def netmask_to_prefix(netmask_str):
        """Convert '255.255.255.0' -> 24. Returns None on parse failure."""
        if not netmask_str:
            return None
        try:
            parts = netmask_str.split(".")
            if len(parts) != 4:
                return None
            n = 0
            for p in parts:
                n = (n << 8) | int(p)
            inv = (~n) & 0xFFFFFFFF
            if (inv & (inv + 1)) != 0:
                return None
            return bin(n).count("1")
        except (ValueError, AttributeError):
            return None

    def sanitize_prefix(raw_prefix, af):
        """Return raw_prefix iff it's a sensible CIDR for af, else af_bitlen(af).

        Windows iphlpapi.GetAdaptersAddresses leaves OnLinkPrefixLength
        as a UCHAR (0-255). For Teredo / 6to4 / ISATAP / NDIS-WAN
        miniports the field is often uninitialised or filled with a
        sentinel, so a value like 218 or 255 leaks through. Clamp here
        rather than letting it propagate -- a host route fallback
        (af_bitlen) is the safest default and keeps the rest of the
        adapter walk going.
        """
        max_bits = af_bitlen(af)
        if raw_prefix is None:
            return max_bits
        try:
            n = int(raw_prefix)
        except (TypeError, ValueError):
            log(fstr(
                "win_iphlpapi: unparseable prefix {0!r} for af={1}; "
                "defaulting to /{2}",
                (raw_prefix, af, max_bits),
            ))
            return max_bits
        if n < 0 or n > max_bits:
            log(fstr(
                "win_iphlpapi: out-of-range prefix {0} for af={1} "
                "(valid 0..{2}); defaulting to /{2}",
                (n, af, max_bits),
            ))
            return max_bits
        return n

    if_infos = []
    for friendly, info in interfaces.items():
        addr_info = {IP4: [], IP6: []}
        for v4 in info[socket.AF_INET]:
            try:
                ipr = IPRange(v4["addr"])
            except (ValueError, TypeError):
                continue
            host_limit = sanitize_prefix(v4.get("prefix"), IP4) or af_bitlen(IP4)
            if host_limit == af_bitlen(IP4):
                fallback_prefix = netmask_to_prefix(v4_masks.get(v4["addr"]))
                if fallback_prefix is not None and fallback_prefix < af_bitlen(IP4):
                    log(fstr(
                        "win_iphlpapi: GetAdaptersInfo fallback prefix /{0} "
                        "for v4 {1} (GetAdaptersAddresses returned /{2})",
                        (fallback_prefix, v4["addr"], host_limit),
                    ))
                    host_limit = fallback_prefix
            try:
                netmask = cidr_to_netmask_v4(host_limit)
            except (ValueError, TypeError):
                log_exception()
                continue
            addr_info[IP4].append({
                "addr": v4["addr"],
                "af": IP4,
                "host_limit": host_limit,
                "netmask": netmask,
            })
        for v6 in info[socket.AF_INET6]:
            try:
                ipr = IPRange(v6["addr"])
            except (ValueError, TypeError):
                continue
            host_limit = sanitize_prefix(v6.get("prefix"), IP6) or af_bitlen(IP6)
            # netifaces doesn't fill IPv6 netmask in any meaningful way
            # cross-platform; the existing PS1 path leaves it omitted
            # and downstream consumers compute reach via host_limit.
            addr_info[IP6].append({
                "addr": v6["addr"],
                "af": IP6,
                "host_limit": host_limit,
                "netmask": None,
            })

        # Drop addressless adapters; downstream selectors trip on them.
        if not addr_info[IP4] and not addr_info[IP6]:
            continue

        # XP runs TCPIP and TCPIP6 as separate services with distinct
        # interface index spaces, so the v4 ifindex is the WRONG scope
        # for v6 link-local binds. Vista+ unified the stacks and the
        # two indices coincide. Surface them separately so downstream
        # callers (apply_nic_pin_sockopts, link-local connect/bind)
        # can pick the right one. Existing "no" stays as the v4 index
        # for backwards compat with the rest of the netifaces shim.
        v4_ifindex = info["ifindex"] or info["ipv6_ifindex"]
        v6_ifindex = info["ipv6_ifindex"] or info["ifindex"]
        # Surface adapter description alongside friendly name so the
        # netifaces shim can register the interface under both. WMIC
        # historically returned the description string ("Intel(R)
        # 82574L Gigabit Network Connection"), while iphlpapi returns
        # FriendlyName ("Local Area Connection" / "Ethernet0"). Code
        # that filters by --nic shouldn't break depending on which
        # loader resolved the interface; keeping both names lets
        # either match.
        if_infos.append({
            "guid": info.get("guid") or friendly,
            "name": friendly,
            "description": info.get("description") or "",
            "no": v4_ifindex,
            "v6_no": v6_ifindex,
            "mac": info["mac"],
            "addr": addr_info,
            "gws": {IP4: None, IP6: None},
            "defaults": [],
        })

    return if_infos
