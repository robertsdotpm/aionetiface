"""Thin wrappers and helpers around Python sockets."""
import socket
import struct
from typing import Any, Optional
from ..utility.utils import fstr, log, log_exception, to_b
from .net_defs import IP4, IP6, TCP, NET_CONF, NOT_WINDOWS, NIC_BIND, LOOPBACK_BIND


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

    try:
        try:
            is_default = route.interface.is_default(route.af)
        except (OSError, AttributeError):
            log_exception()
            is_default = True

        if NOT_WINDOWS:
            if not is_default:
                sock.setsockopt(
                    socket.SOL_SOCKET, 25, to_b(route.interface.id),
                )
        else:
            try:
                if_index = int(route.interface.id)
                if route.af == IP4:
                    sock.setsockopt(
                        socket.IPPROTO_IP, 31,
                        struct.pack("!I", if_index),
                    )
                else:
                    sock.setsockopt(
                        socket.IPPROTO_IPV6, 31,
                        struct.pack("=I", if_index),
                    )
            except (OSError, ValueError, TypeError):
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
