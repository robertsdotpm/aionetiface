"""Thin wrappers and helpers around Python sockets."""
import socket
import struct
from typing import Any, Optional
from ..utility.utils import fstr, log, log_exception, to_b
from .net_defs import IP4, IP6, TCP, NET_CONF, NOT_WINDOWS, IS_DARWIN, IS_BSD, NIC_BIND, LOOPBACK_BIND


def apply_nic_pin_sockopts(sock: Any, route: Any) -> None:
    """Pin sock to route.interface so egress + bound source agree on multi-NIC hosts.

    Linux: SO_BINDTODEVICE for non-default interfaces only (root not
    required for the default route).  Windows: IP_UNICAST_IF /
    IPV6_UNICAST_IF unconditionally -- on multi-default-route hosts
    (LAN + cellular, multi-homed corporate) the kernel would otherwise
    round-robin between equal-metric routes and the bound source IP
    wouldn't match the picked path, dropping packets silently.

    Extracted from socket_factory so synchronous code paths (the
    blocking punch engines that bind raw sockets in an executor
    thread) can apply the same NIC pinning without going through the
    async factory.  Single source of truth: socket_factory delegates
    here too.
    """
    if route is None or route.interface is None:
        return

    # XP: v4 and v6 interface index spaces differ. Interface
    # .get_nic_id(af) dispatches to the right per-AF ifindex via
    # the netifaces backend (Windows shim with split iphlpapi
    # data) and falls back cleanly on POSIX where v4/v6 are
    # unified.
    iface_id = route.interface.get_nic_id(route.af)
    if iface_id is None:
        # Default route on Windows occasionally yields a route whose
        # interface object exists but whose .id is None (probe at
        # interface-load time hadn't returned a nic_no yet). Skip the
        # NIC-pin sockopt cleanly rather than letting int(None) raise
        # a TypeError that's caught + logged as a stacktrace -- the
        # fallback is "let the kernel pick", which is the right
        # behaviour for a default route anyway.
        return

    try:
        try:
            is_default = route.interface.is_default(route.af)
        except (OSError, AttributeError):
            log_exception()
            is_default = True

        if NOT_WINDOWS:
            if IS_DARWIN:
                # macOS/iOS: SO_BINDTODEVICE not available; use IP_BOUND_IF
                # (IPv4, IPPROTO_IP/25) or IPV6_BOUND_IF (IPv6, IPPROTO_IPV6/125)
                # to pin egress to the chosen interface by index.
                # iface_id is the interface name string on POSIX; convert to
                # numeric index via if_nametoindex before packing into the sockopt.
                try:
                    if_index = route.interface.get_nic_id(route.af)
                    if not if_index:
                        return
                    if route.af == IP4:
                        sock.setsockopt(socket.IPPROTO_IP, 25, struct.pack("=I", if_index))
                    else:
                        ipproto_ipv6 = getattr(socket, "IPPROTO_IPV6", 41)
                        sock.setsockopt(ipproto_ipv6, 125, struct.pack("=I", if_index))
                    log(
                        "apply_nic_pin_sockopts: darwin pinned socket to "
                        "if_index={0} af={1}".format(if_index, route.af)
                    )
                except (OSError, ValueError, TypeError) as exc:
                    log(
                        "apply_nic_pin_sockopts: darwin pin FAILED iface_id={0} "
                        "af={1}: {2} ({3})".format(
                            iface_id, route.af, type(exc).__name__, repr(exc),
                        )
                    )
            elif IS_BSD:
                # FreeBSD/OpenBSD/NetBSD: use IP_BOUND_IF (IPPROTO_IP/25) and
                # IPV6_BOUND_IF (IPPROTO_IPV6/125) -- same option numbers and
                # semantics as Darwin.  Falls back silently on BSD variants
                # that don't expose the option (ENOPROTOOPT).
                try:
                    if_index = route.interface.get_nic_id(route.af)
                    if not if_index:
                        return
                    if route.af == IP4:
                        sock.setsockopt(socket.IPPROTO_IP, 25, struct.pack("=I", if_index))
                    else:
                        ipproto_ipv6 = getattr(socket, "IPPROTO_IPV6", 41)
                        sock.setsockopt(ipproto_ipv6, 125, struct.pack("=I", if_index))
                    log(
                        "apply_nic_pin_sockopts: bsd pinned socket to "
                        "if_index={0} af={1}".format(if_index, route.af)
                    )
                except (OSError, ValueError, TypeError) as exc:
                    log(
                        "apply_nic_pin_sockopts: bsd pin FAILED iface_id={0} "
                        "af={1}: {2} ({3})".format(
                            iface_id, route.af, type(exc).__name__, repr(exc),
                        )
                    )
            elif not is_default:
                # Linux: SO_BINDTODEVICE (SOL_SOCKET option 25) for non-default
                # interfaces pins egress at the kernel routing level.
                sock.setsockopt(socket.SOL_SOCKET, 25, to_b(iface_id))
        else:
            try:
                if_index = int(iface_id)
                if route.af == IP4:
                    # IP_UNICAST_IF (level=IPPROTO_IP, optname=31) expects the
                    # interface index in NETWORK byte order on Windows. Using
                    # native order ("=I") on little-endian x86 puts the real
                    # index value into the high-order bytes, which Windows
                    # reads as a bogus interface and rejects with WinError
                    # 10049 ("The requested address is not valid in its
                    # context"). The error was caught by the surrounding
                    # try/except so it didn't crash, but the socket was left
                    # unpinned -- connects then went out via whatever NIC the
                    # kernel routing picked, which on multi-NIC hosts could
                    # silently break tcp_punch by missing the intended LAN.
                    sock.setsockopt(
                        socket.IPPROTO_IP, 31,
                        struct.pack("!I", if_index),
                    )
                else:
                    # IPV6_UNICAST_IF (level=IPPROTO_IPV6, optname=31) takes
                    # the index in HOST byte order, unlike its v4 sibling.
                    # Python 3.5 on Vista/XP doesn't expose
                    # socket.IPPROTO_IPV6 as an attribute even though the
                    # OS supports the sockopt; fall back to the IANA
                    # constant 41 (== IPPROTO_IPV6 on every platform we
                    # care about) so v6 sockets still get NIC-pinned on
                    # those hosts. Without this, the AttributeError
                    # propagated and broke every v6 socket creation,
                    # which is why v6 STUN was failing 100% on Vista
                    # despite raw-socket STUN reaching 31/40 servers.
                    ipproto_ipv6 = getattr(socket, "IPPROTO_IPV6", 41)
                    sock.setsockopt(
                        ipproto_ipv6, 31,
                        struct.pack("=I", if_index),
                    )
                log(
                    "apply_nic_pin_sockopts: pinned socket to "
                    "if_index={0} af={1} is_default={2}".format(
                        if_index, route.af, is_default,
                    )
                )
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                log(
                    "apply_nic_pin_sockopts: pin FAILED if_index={0} "
                    "af={1}: {2} ({3})".format(
                        iface_id, route.af, type(exc).__name__, repr(exc),
                    )
                )
                log_exception()
    except OSError:
        log_exception()


async def socket_factory(
    route: Any,
    dest_addr: Optional[Any] = None,
    sock_type: int = TCP,
    conf: Optional[Any] = None,
) -> Optional[Any]:
    """Create, configure, and bind a socket for the given route and optional destination, returning it or None on failure."""
    if conf is None:
        conf = NET_CONF
    # Check route is bound.
    if not route.resolved:
        raise ValueError("You didn't bind the route!")

    # Check addresses were processed.
    if dest_addr is not None:
        if not dest_addr.resolved:
            raise ValueError("net sock factory: dest addr not resolved")
        # If dest_addr was a domain = AF_ANY.
        # Stills needs a sock type tho
        if route.af not in dest_addr.supported():
            raise ValueError("Route af not supported by dest addr")

    # Create socket.
    sock = socket.socket(route.af, sock_type, conf["sock_proto"])

    # Useful to cleanup sockets right away.
    if conf["linger"] is not None:
        # Enable linger and set it to its value.
        linger = struct.pack("ii", 1, conf["linger"])
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)

    # Reuse port to avoid errors.
    if conf["reuse_addr"]:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass

    # Set broadcast option.
    if conf["broadcast"]:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # This may be set by the async wrappers.
    sock.settimeout(0)

    # Pin egress to route.interface on multi-NIC hosts. Loopback dest
    # ranges through any NIC at L3 so this is a no-op for them; the
    # helper itself handles route.interface=None safely.
    apply_nic_pin_sockopts(sock, route)

    # Default = use any IPv4 NIC.
    # For IPv4 -- bind address
    # depends on destination type.
    bind_flag = NIC_BIND
    if dest_addr is not None:
        # Get loopback working.
        if dest_addr.is_loopback:
            bind_flag = LOOPBACK_BIND

    # Choose bind tup to use.
    bind_tup = route.bind_tup(flag=bind_flag)

    # Attempt to bind to the tup.
    try:
        sock.bind(bind_tup)
        return sock
    except OSError:
        error = fstr(
            """
        Could not bind to interface
        af = {0}
        sock = {1}"
        bind_tup = {2}
        """,
            (
                route.af,
                sock,
                bind_tup,
            ),
        )
        log(error)
        log_exception()
        if sock is not None:
            sock.close()
        return None
