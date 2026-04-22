"""Bind policy application to sockets."""
import copy
from typing import Any, List, Optional, Tuple
from ...net.net_defs import IP6, LOOPBACK_BIND, NIC_BIND
from .bind_rules import binder_async
from .bind_utils import bind_closure


"""
Mostly this class will not be used directly by users.
It's code is also shitty for res. Routes have superseeded this.
"""


class Bind:
    """Represents a socket bind configuration for a particular interface and address family."""

    def __init__(
        self,
        interface: Optional[Any],
        af: int,
        port: int = 0,
        ips: Optional[Any] = None,
        leave_none: int = 0,
    ) -> None:
        # if IS_DEBUG:
        # assert("Interface" in str(type(interface)))
        self.ips = ips
        self.interface = interface
        self.af = af
        self.resolved = False
        self.bind_port = port

        # Will store a tuple that can be passed to bind.
        self._bind_tups = ()
        if not hasattr(self, "bind"):
            self.bind = bind_closure(self, binder_async)

    def __await__(self) -> Any:
        return self.bind().__await__()

    async def res(self) -> "Bind":
        """Resolve the bind parameters by calling the internal bind closure."""
        return await self.bind()

    async def start(self) -> None:
        """Trigger resolution of the bind configuration."""
        await self.res()

    def bind_tup(
        self, port: Optional[int] = None, flag: int = NIC_BIND
    ) -> Tuple[Any, ...]:
        """Return the (ip, port) tuple to pass to socket.bind(), optionally overriding the port."""
        # Handle loopback support.
        if flag == LOOPBACK_BIND:
            if self.af == IP6:
                return ("::1", self.bind_port)
            return ("127.0.0.1", self.bind_port)

        # Spawn a new copy of the bind tup (if needed.)
        tup = self._bind_tups
        if port is not None:
            tup = copy.deepcopy(tup)
            tup[1] = port

        # IP may not be set if invalid type of IP passed to Bind
        # and then the wrong flag type was used with it.
        if tup[0] is None:
            e = "Bind ip is none. Possibly an invalid IP "
            e += "(private and not public or visa versa) "
            e += "was passed to Bind for IPv6 causing no "
            e += "IP for the right type to be set. "
            e += "Also possible there were no link locals."
            raise ValueError(e)

        # log("> binding to tup = {}".format(tup))
        return tup

    def supported(self) -> List[int]:
        """Return a one-element list with the address family this Bind was configured for."""
        return [self.af]
