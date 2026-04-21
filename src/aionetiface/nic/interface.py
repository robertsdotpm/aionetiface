"""
There's a chance that if you run tests too closely in the same duration. Or a test
suite with lots of calls to resolve external IPs then you hit the same servers many
times. Then those servers interpret it as a DoS and add a temp limit on messages.
That would make tests fail sometimes when it otherwise works. Caching addresses
for IFs in some way could be a good idea.
"""

import copy
import platform
import pprint
from typing import Any, Dict, Iterator, List, Optional, Union
from ..utility.utils import async_test, fstr
from ..net.net_defs import DUEL_STACK, IP4, IP6, UNKNOWN_STACK, VALID_STACKS
from ..net.address import Address
from .route.route_pool import RoutePool
from .nat.nat_utils import nat_info
from .nat.nat_test import nic_load_nat
from .load_interface import load_interface
from .interface_utils import is_nic_default, nic_from_dict, nic_to_dict
from .default_interface import use_default_interface
from ..entrypoint import aionetiface_setup_event_loop


# Used for specifying the interface for sending out packets on
# in TCP streams and UDP streams.
# Note: number of bad STUN servers means timeout should be higher.
# Maybe make this proportional to last server freshness age.
class Interface():
    def __init__(self, name: Optional[Any] = None, stack: int = DUEL_STACK, nat: Optional[Dict[str, Any]] = None, netifaces: Optional[Any] = None, timeout: int = 4) -> None:
        super().__init__()
        self.__name__ = "Interface"
        if name == "default":
            use_default_interface(self)
            return

        # Otherwise load everything.
        self.resolved = False
        self.netiface_index = None
        self.id = self.mac = self.nic_no = None
        self.nat = nat or nat_info()
        self.name = name
        self.rp = {IP4: RoutePool(), IP6: RoutePool()}
        self.v4_lan_ips = []
        self.guid = None
        self.netifaces = netifaces or Interface.get_netifaces()
        self.timeout = timeout

        # Check NAT is valid if set.
        if nat is not None:
            assert(isinstance(nat, dict))
            assert(nat.keys() == nat_info().keys())

        # Can provide a stack type to skip processing unsupported AFs.
        # Otherwise all AFs are checked when start() is called.
        self.stack = stack
        assert(self.stack in VALID_STACKS)

    async def start(self, netifaces: Optional[Any] = None, min_agree: int = 2, max_agree: int = 5, timeout: int = 4) -> "Interface":
        # Declared in load_interface.py.
        return await load_interface(
            nic=self,
            netifaces=netifaces,
            min_agree=min_agree,
            max_agree=max_agree,
            timeout=timeout,
        )
    
    async def load_nat(self, nat_tests: int = 5, delta_tests: int = 12, timeout: int = 4) -> Dict[str, Any]:
        # Try main decentralized NAT test approach.
        nat_type, delta = await nic_load_nat(
            self,
            nat_tests,
            delta_tests,
            timeout=timeout
        )
            
        # Load NAT type and delta info.
        # On a server should be open.
        nat = nat_info(nat_type, delta)
        return self.set_nat(nat)
    
    def set_nat(self, nat: Dict[str, Any]) -> Dict[str, Any]:
        assert(isinstance(nat, dict))
        assert(nat.keys() == nat_info().keys())
        self.nat = nat
        return nat
    
    def get_scope_id(self) -> Any:
        assert(self.resolved)

        # Interface specified by no on windows.
        if platform.system() == "Windows":
            return self.nic_no
        else:
            # Other platforms just use the name
            return self.name

    def nic(self, af: int) -> Optional[str]:
        # Sanity check.
        if self.resolved:
            assert(af in self.what_afs())
        if self.rp != {} and len(self.rp[af].routes):
            return self.route(af).nic()

    def route(self, af: Optional[int] = None, bind_port: int = 0) -> Any:
        if not self.resolved:
            assert(af is not None)

        # Sanity check.
        if self.resolved:
            af = af or self.supported()[0]
            assert(af in self.what_afs())

        # Main route is first.
        if af in self.rp:
            if len(self.rp[af].routes):
                return copy.deepcopy(self.rp[af].routes[0])

        raise Exception(fstr("No route for {0} found.", (af,)))

    def is_default_patch(self, af: int, gws: Optional[Any] = None) -> bool:
        return True

    def is_default(self, af: int, gws: Optional[Any] = None) -> bool:
        """
        Return True if this interface is the default route for address family af.

        Accepting a gateway list (gws) avoids a repeated system call, at the
        cost of stale results if the routing table changes (e.g. wifi disconnect)
        while the list is held.
        """
        return is_nic_default(self, af, gws)
    
    def supported(self, skip_resolve: int = 0) -> List[int]:
        if not skip_resolve:
            assert(self.resolved)

        if self.stack == UNKNOWN_STACK:
            raise Exception("Unknown stack")

        if self.stack == DUEL_STACK:
            return sorted([IP4, IP6])
        else:
            return sorted([self.stack])

    def what_afs(self) -> List[int]:
        assert(self.resolved)
        return self.supported()
    
    def __await__(self) -> Any:
        return self.start(timeout=self.timeout).__await__()

    def to_dict(self) -> Dict[str, Any]:
        return nic_to_dict(self)

    @staticmethod
    def get_netifaces() -> Optional[Any]:
        return None

    @staticmethod
    def list() -> List[str]:
        return Interface.get_netifaces().interfaces()

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Interface":
        return nic_from_dict(d, Interface)

    # Make this interface printable because it's useful.
    def __str__(self) -> str:
        return pprint.pformat(self.to_dict())

    # Show a representation of this object.
    def __repr__(self) -> str:
        nic_info = str(self)
        return "Interface.from_dict(%s)" % (nic_info)

    # Pickle.
    def __getstate__(self) -> Dict[str, Any]:
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state: Dict[str, Any]) -> None:
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    # Make all nic IPs across route pools a generator.
    # Return both the nic_ipr and route they belong to.
    def __iter__(self) -> Iterator[Any]:
        seen = set()
        for af in (IP4, IP6):
            for route in self.rp[af]:
                for nic_ipr in route.nic_ips + route.link_locals:
                    if nic_ipr not in seen:
                        nic_ipr.route = route
                        seen.add(nic_ipr)
                        yield nic_ipr

if __name__ == "__main__":  # pragma: no cover
    async def demo_interface() -> None:
        nic = Interface("default")
        r = nic.route()
        d = await Address("google.com", 80, nic)
        print(d)

    async_test(demo_interface)

