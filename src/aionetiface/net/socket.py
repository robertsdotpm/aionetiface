"""Thin wrappers and helpers around Python sockets."""
import socket
import struct
from typing import Any, Optional
from ..utility.utils import fstr, log, log_exception, to_b
from .net_defs import IP4, IP6, TCP, NET_CONF, NOT_WINDOWS, NIC_BIND, LOOPBACK_BIND


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

    # Bind to the specific interface if set. On Linux, root is sometimes
    # needed to bind to a non-default interface, but not the default one.
    #
    # Skip the device-pinning sockopt when the destination is loopback:
    # 127.x and ::1 don't route through any physical NIC, so device-
    # binding the connect socket makes the kernel return EINVAL on
    # connect(). The interface metadata (NIC IP, route family) still
    # applies normally for bind() below; this only suppresses the
    # L2-pin sockopt for loopback destinations.
    try:
        if route.interface is not None:
            # TODO: probably cache this.
            try:
                is_default = route.interface.is_default(route.af)
            except (OSError, AttributeError):
                log_exception()
                is_default = True

            if NOT_WINDOWS:
                # Linux: SO_BINDTODEVICE takes the interface name as
                # bytes. Skip when the route is the system default
                # because root is sometimes required for non-default
                # devices and the default route doesn't need pinning
                # (the OS picks it anyway).
                if not is_default:
                    sock.setsockopt(
                        socket.SOL_SOCKET, 25, to_b(route.interface.id),
                    )
            else:
                # Windows: IP_UNICAST_IF / IPV6_UNICAST_IF (option 31).
                # Forces egress through the specified interface
                # regardless of routing-table preference. Critical on
                # hosts with multiple equal-metric default routes (LAN
                # + cellular, multi-homed corporate, ...) where the
                # kernel would otherwise round-robin between them and
                # the bound source IP wouldn't match the picked path
                # -- packets drop silently and TCP connect times out.
                # With IP_UNICAST_IF set, source and egress always
                # agree.
                #
                # Set unconditionally (no is_default guard): on a
                # single-NIC machine the option is a no-op (the OS
                # would pick that NIC anyway); on multi-default-route
                # machines is_default is unreliable because the probe
                # at startup may have picked a different NIC than the
                # real connect(), so we can't trust it as a gating
                # condition.
                #
                # IPv4 takes the if_index in NETWORK byte order; IPv6
                # in host byte order. route.interface.id on Windows is
                # the integer if_index (nic_no).
                try:
                    if_index = int(route.interface.id)
                    if route.af == IP4:
                        # IPPROTO_IP = 0; IP_UNICAST_IF = 31
                        sock.setsockopt(
                            socket.IPPROTO_IP, 31,
                            struct.pack("!I", if_index),
                        )
                    else:
                        # IPPROTO_IPV6 = 41; IPV6_UNICAST_IF = 31
                        sock.setsockopt(
                            socket.IPPROTO_IPV6, 31,
                            struct.pack("=I", if_index),
                        )
                except (OSError, ValueError, TypeError):
                    # If if_index is unparsable or the option isn't
                    # supported on this Windows build, fall back to
                    # bind-source-only behaviour. Better than crashing
                    # the socket creation.
                    log_exception()
    except OSError:
        log_exception()
        # Try continue -- an exception isn't always accurate.
        # E.g. Mac OS X doesn't support that sockopt but still works.

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
