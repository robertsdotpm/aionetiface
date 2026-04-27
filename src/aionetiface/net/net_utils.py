"""Low-level socket and address utility functions."""
import socket
import struct
import ipaddress
from typing import Any, Optional, Tuple, Union
import re
from ..utility.utils import (
    ip_f,
    log,
    log_exception,
    to_h,
    to_i,
    to_s,
)
from .net_defs import (
    HOST_TYPE_DOMAIN, HOST_TYPE_IP, AF_ANY, AF_NONE, AF_LINK, AF_INET, AF_INET6,
    TCP, STREAM, SOCK_STREAM, UDP, DGRAM, SOCK_DGRAM, RUDP,
    INTERFACE_UNKNOWN, INTERFACE_ETHERNET, INTERFACE_WIRELESS, UNKNOWN_STACK,
    IP4, V4, V4_STACK, IP6, V6, V6_STACK, V6_LINK_LOCAL_MASK, DUEL_STACK,
    VALID_AFS, VALID_STACKS, NET_NON_BLOCKING, NET_BLOCKING,
    NET_MAX_MSG_NO, NET_MAX_MSGS_SIZEOF,
    ZERO_NETMASK_IP4, ZERO_NETMASK_IP6, BLACK_HOLE_IPS,
    VALID_LOOPBACKS, VALID_ANY_ADDR, ANY_ADDR, LOOPBACK_BIND,
    IPA_TYPES, ipa_types, ANY_ADDR_LOOKUP, LOCALHOST_LOOKUP, PROTO_LOOKUP,
    DATAGRAM_TYPES, STREAM_TYPES, V4_VALID_ANY, V6_VALID_ANY,
    V6_VALID_LOCALHOST, V4_VALID_LOCALHOST, VALID_LOCALHOST,
    NIC_BIND, EXT_BIND,
    IP_PRIVATE, IP_PUBLIC, IP_APPEND, IP_BIND_TUP,
    NOT_WINDOWS, SUB_ALL, NET_CONF, FakeSocket,
)


def af_to_v(af: int) -> int:
    """Convert a socket address family constant to an IP version number (4 or 6)."""
    return 4 if af == IP4 else 6


def v_to_af(v: int) -> int:
    """Convert an IP version number (4 or 6) to the corresponding socket address family constant."""
    return IP4 if v == 4 else IP6


def i_to_af(x: int) -> int:
    """Convert the raw integer socket family value (2=IPv4, other=IPv6) to an AF constant."""
    return IP4 if x == 2 else IP6


def af_bitlen(af: int) -> int:
    """Return the bit width of the address family (32 for IPv4, 128 for IPv6)."""
    return 32 if af == IP4 else 128


def sock_has_data(sock: Any) -> bool:
    """Return True if the socket has at least one byte available to read without blocking."""
    try:
        ready = sock.recv(1, socket.MSG_PEEK)
        if ready:
            return True
    except BlockingIOError:
        return False

    return False


def af_from_ip_s(ip_s: Union[str, bytes]) -> int:
    """Determine the address family (IP4 or IP6) from an IP address string."""
    ip_s = to_s(ip_s)
    ip_obj = ip_f(ip_s)
    return v_to_af(ip_obj.version)


def ip_str_to_int(ip_str: str) -> int:
    """Convert a dotted-decimal or colon-separated IP address string to an integer."""
    ip_obj = ipaddress.ip_address(ip_str)
    if ip_obj.version == 4:
        pack_ip = socket.inet_aton(ip_str)
        return struct.unpack("!L", pack_ip)[0]
    else:
        ip_str = str(ip_obj.exploded)
        hex_str = to_h(socket.inet_pton(AF_INET6, ip_str))
        return to_i(hex_str)


def netmask_to_cidr(netmask: str) -> int:
    """Convert a dotted-decimal netmask or /N string to a CIDR prefix length integer."""
    # Already a host_limit.
    if "/" in netmask:
        return int(netmask.replace("/", ""))

    as_int = ip_str_to_int(netmask)
    return bin(as_int).count("1")


def cidr_to_netmask(host_limit: int, af: int) -> str:
    """Convert a CIDR prefix length to a dotted-decimal (IPv4) or exploded (IPv6) netmask string.

    Windows iphlpapi.GetAdaptersAddresses can return out-of-range
    OnLinkPrefixLength values for some interfaces (e.g. 255 sentinel,
    or values left over from another address family on transition
    technologies / 6to4 / Teredo). Without clamping, "1" * host_limit
    overflows the 32-/128-bit space and IPv4Address / IPv6Address
    raise AddressValueError during interface enumeration. Clamp to
    [0, end] so an out-of-range value is treated as a host route,
    which is the most restrictive safe default and preserves the
    rest of the netifaces walk.
    """
    end = 32 if af == AF_INET else 128
    if host_limit < 0:
        host_limit = 0
    elif host_limit > end:
        host_limit = end
    buf = "1" * host_limit
    buf += "0" * (end - host_limit)
    n = int(buf, 2)
    if af == AF_INET:
        return str(ipaddress.IPv4Address(n))
    else:
        return str(ipaddress.IPv6Address(n).exploded)


def toggle_host_bits(netmask: str, ip_str: str, toggle: int = 0) -> str:
    """Zero or set all host bits in ip_str according to the netmask (toggle=0 clears, toggle=1 sets)."""
    ip_obj = ipaddress.ip_address(ip_str)
    if "/" in netmask:
        host_limit = int(netmask.split("/")[-1])
    else:
        host_limit = netmask_to_cidr(netmask)
    as_int = ip_str_to_int(ip_str)
    as_bin = bin(as_int)[2:]
    net_part = as_bin[:host_limit]
    if not toggle:
        host_part = "0" * (len(as_bin) - len(net_part))
    else:
        host_part = "1" * (len(as_bin) - len(net_part))

    bin_result = net_part + host_part
    n_result = int(bin_result, 2)
    if ip_obj.version == 4:
        return str(ipaddress.IPv4Address(n_result))
    else:
        return str(ipaddress.IPv6Address(n_result).exploded)


def get_broadcast_ip(netmask: str, gw_ip: str) -> str:
    """Return the broadcast address for the subnet defined by netmask and gw_ip."""
    return toggle_host_bits(netmask, gw_ip, toggle=1)


"""
- Removes %interface name after an IPv6.
- Expands shortened / or abbreviated IPs to
their longest possible form.

Why? Because comparing IPs considers IPv6s
to be 'different' if they have different interfaces
attached / missing them.

Or if you compare the same compressed IPv6 to
its uncompressed form (textually) then it
will give a false negative.
"""


def ipv6_norm(ip_val: Union[str, bytes, int]) -> str:
    """Return the fully-exploded string form of an IPv6 address, or unchanged for IPv4."""
    ip_obj = ipaddress.ip_address(ip_val)
    if ip_obj.version == 6:
        return str(ip_obj.exploded)

    return str(ip_obj)


def ip_strip_if(ip: Union[str, bytes]) -> Union[str, bytes]:
    """Remove the interface scope identifier (e.g. %eth0) from an IPv6 address string."""
    if isinstance(ip, str):
        if "%" in ip:
            parts = ip.split("%")
            return parts[0]

    return ip


def ip_strip_cidr(ip: Union[str, bytes]) -> Union[str, bytes]:
    """Remove a CIDR suffix (e.g. /24) from an IP address string."""
    if isinstance(ip, str):
        if "/" in ip:
            ip = ip.split("/")[0]

    return ip


def ip_norm(ip: Union[str, bytes]) -> str:
    """Normalise an IP address by stripping scope IDs and CIDR, and exploding IPv6."""
    # Strip interface scope id.
    ip = ip_strip_if(ip)

    # Strip CIDR.
    ip = ip_strip_cidr(ip)

    # Convert IPv6 to exploded form
    # if it's IPv6.
    ip = ipv6_norm(ip)

    return ip


def mac_norm(mac: str) -> str:
    """Normalise a MAC address to a lowercase hex string with no separators."""
    parts = re.split("[:.-]", mac)
    parts = [part.zfill(2).lower() for part in parts]
    return "".join(parts)


def client_tup_norm(client_tup: Optional[Tuple[Any, ...]]) -> Optional[Tuple[str, int]]:
    """Return a (normalised_ip, port) tuple, or None if client_tup is None."""
    if client_tup is None:
        return None

    ip = ip_norm(client_tup[0])
    return (ip, client_tup[1])


def is_socket_closed(sock: Any) -> bool:
    """Return True if the socket appears to be closed or has received a connection reset."""
    try:
        # this will try to read bytes without blocking and also without removing them from buffer (peek only)
        data = sock.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
        if not data:
            return True
    except BlockingIOError:
        return False  # socket is open and reading from it would block
    except ConnectionResetError:
        return True  # socket was closed for some other reason
    except OSError:
        log("unexpected exception when checking if a socket is closed")
        return False
    return False


# Hack: determine which local interface is on the path to a private destination.
#
# When connecting to a private address in the LAN, binding to the wrong
# local interface IP means the kernel can't route the packet.  The proper fix
# is to include full subnet information in routing, but until then we use a
# zero-timeout connect() to let the OS pick the right source interface, then
# read back the bound address.
#
# This makes p2p connections to LAN hosts and to services on the same machine
# more robust.
def determine_if_path(af: int, dest: str) -> Optional[str]:
    """Use a zero-timeout UDP connect to ask the OS which local IP would be used to reach dest."""
    # Setup socket for connection.
    src_ip = None
    with socket.socket(af, UDP) as s:
        # We don't care about connection success.
        # But avoiding delays is important.
        s.settimeout(0)
        # Large port avoids perm errors.
        # Doesn't matter if it exists or not.
        s.connect((dest, 12345))

        # Get the interface bind address.
        src_ip = s.getsockname()[0]

    return src_ip


def avoid_time_wait(pipe: Any) -> None:
    """Set SO_LINGER=0 on the pipe's socket so the port is released immediately on close."""
    try:
        sock = pipe.sock
        linger = struct.pack("ii", 1, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    except OSError:
        # Not guaranteed on windows.
        log_exception()


# Not used presently but may be useful in future.
async def safe_sock_connect(loop: Any, sock: Any, dest: Tuple[str, int]) -> bool:
    """Attempt to connect sock to dest, returning True on success and False on refusal or OS error."""
    try:
        await loop.sock_connect(sock, dest)
        return True
    except ConnectionRefusedError:
        log("Connection refused: " + str(dest))
        return False
    except OSError as e:
        # Handles e.g. ENETUNREACH, ETIMEDOUT, ECONNRESET
        log("Socket connect error to " + str(dest) + ":" + str(e))
        return False
