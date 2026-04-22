from typing import Any, Optional
from ..utility.utils import *
from .net_utils import *


async def socket_factory(
    route: Any,
    dest_addr: Optional[Any] = None,
    sock_type: int = TCP,
    conf: Any = NET_CONF,
) -> Optional[Any]:
    # Check route is bound.
    if not route.resolved:
        raise Exception("You didn't bind the route!")

    # Check addresses were processed.
    if dest_addr is not None:
        if not dest_addr.resolved:
            raise Exception("net sock factory: dest addr not resolved")
        else:
            # if not dest_addr.port:
            #    raise Exception("net: dest port is 0!")

            # If dest_addr was a domain = AF_ANY.
            # Stills needs a sock type tho
            if route.af not in dest_addr.supported():
                raise Exception("Route af not supported by dest addr")

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
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
            # Doesn't work on Windows.

    # Set broadcast option.
    if conf["broadcast"]:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # This may be set by the async wrappers.
    sock.settimeout(0)

    """
    Bind to specific interface if set.
    On linux root is sometimes needed to
    bind to a non-default interface.
    If the interface is default for
    address type then no need to
    specifically bind to it.
    """

    try:
        if route.interface is not None:
            # TODO: probably cache this.
            try:
                is_default = route.interface.is_default(route.af)
            except (OSError, AttributeError):
                log_exception()
                is_default = True

            if not is_default and NOT_WINDOWS:
                sock.setsockopt(socket.SOL_SOCKET, 25, to_b(route.interface.id))
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
