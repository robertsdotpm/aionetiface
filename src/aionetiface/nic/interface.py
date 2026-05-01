"""
There's a chance that if you run tests too closely in the same duration. Or a test
suite with lots of calls to resolve external IPs then you hit the same servers many
times. Then those servers interpret it as a DoS and add a temp limit on messages.
That would make tests fail sometimes when it otherwise works. Caching addresses
for IFs in some way could be a good idea.

Windows XP gateway-detection caveat
-----------------------------------
On Windows XP, the OS introspection APIs (PowerShell Get-NetIPInterface,
WMIC Win32_NetworkAdapterConfiguration, netsh interface ip show) sometimes
return a *blank* default gateway for an adapter even when the adapter is
fully working: ``ipconfig /all`` shows the gateway, ``ping`` to it succeeds,
and the route is in the routing table.  The blank-gateway condition flaps
intermittently -- often correlated with DHCP lease renewals -- and makes
NIC discovery, STUN, and PNP signaling silently flake.

Workaround: configure a *fixed* gateway IP and a *fixed* metric on the
adapter so the OS never has to re-derive them from DHCP:

    Network Connections > <adapter> > Properties > Internet Protocol (TCP/IP)
        > Properties > Advanced... > IP Settings tab
        > Default gateways:  Add...  set Gateway = 10.0.1.1
                             Untick "Automatic metric"
                             Set "Interface metric" to a fixed value (e.g. 10)
        > OK

The blank-gateway condition is logged at WARNING via win_set_gateways
("blank gateway -- may be a bug"); see code in
nic/netifaces/windows/win_netifaces.py.

This was confirmed empirically: the XP test VM went from ~50% NIC-load
failures under repeated launches to 100% success after the fixed-gateway
+ fixed-metric change.
"""

import copy
import platform
import pprint
from typing import Any, Dict, Iterator, List, Optional
from ..utility.utils import async_test, fstr
from ..net.net_defs import DUEL_STACK, IP4, IP6, UNKNOWN_STACK, VALID_STACKS
from ..net.address import Address
from .route.route_pool import RoutePool
from .nat.nat_utils import nat_info
from .nat.nat_test import nic_load_nat
from .load_interface import load_interface
from .interface_utils import is_nic_default, nic_from_dict, nic_to_dict
from .default_interface import use_default_interface


# Used for specifying the interface for sending out packets on
# in TCP streams and UDP streams.
# Note: number of bad STUN servers means timeout should be higher.
# Maybe make this proportional to last server freshness age.
class Interface:
    """Represents a single network interface with resolved routes, NAT info, and address families."""

    # Process-wide cache of the OS-default pseudo-interface. Populated either
    # eagerly by aionetiface_setup_netifaces() or lazily on first is_default()
    # call. Holds a single Interface("default") whose routes are derived from
    # the kernel's UDP-connect source-IP trick (cross-platform).
    default = None  # type: Optional["Interface"]

    def __init__(
        self,
        name: Optional[Any] = None,
        stack: int = DUEL_STACK,
        nat: Optional[Dict[str, Any]] = None,
        netifaces: Optional[Any] = None,
        timeout: int = 4,
    ) -> None:
        super().__init__()
        if name == "default":
            use_default_interface(self)
            return

        # Otherwise load everything.
        self.resolved = False
        self.netiface_index = None
        self.id = self.mac = self.nic_no = None
        # XP has separate v4 / v6 interface index spaces (TCPIP vs
        # TCPIP6 services); the nic_no surfaced from netifaces is
        # the v4 index and points at the wrong interface for v6
        # binds. Vista+ unified the stacks so v4 and v6 share the
        # index. Per-AF v6_scope_id captured during start() (read
        # from netifaces' fe80::%scope on the matching link-local)
        # so callers that need to bind / connect a link-local v6
        # address use the right scope id regardless of OS. None
        # means "not set; fall back to nic.id" -- the right
        # behaviour on Vista+ where they're the same anyway.
        self.v6_scope_id = None
        self.nat = nat or nat_info()
        self.name = name
        self.rp = {IP4: RoutePool(), IP6: RoutePool()}
        self.v4_lan_ips = []
        self.guid = None
        self.netifaces = netifaces or Interface.get_netifaces()
        self.timeout = timeout

        # Check NAT is valid if set.
        if nat is not None:
            if not isinstance(nat, dict):
                raise TypeError("nat must be a dict")
            if nat.keys() != nat_info().keys():
                raise ValueError("nat keys do not match expected schema")

        # Can provide a stack type to skip processing unsupported AFs.
        # Otherwise all AFs are checked when start() is called.
        self.stack = stack
        if self.stack not in VALID_STACKS:
            raise ValueError(fstr("invalid stack: {0}", (self.stack,)))

    async def start(
        self,
        netifaces: Optional[Any] = None,
        min_agree: int = 2,
        max_agree: int = 5,
        timeout: int = 4,
    ) -> "Interface":
        """Resolve this interface's routes and external IPs by running STUN and NIC discovery."""
        # Declared in load_interface.py.
        return await load_interface(
            nic=self,
            netifaces=netifaces,
            min_agree=min_agree,
            max_agree=max_agree,
            timeout=timeout,
        )

    async def load_nat(
        self, nat_tests: int = 5, delta_tests: int = 12, timeout: int = 4
    ) -> Dict[str, Any]:
        """Run NAT type and port-delta tests for this interface and store the results, returning the nat dict."""
        # Try main decentralized NAT test approach.
        nat_type, delta = await nic_load_nat(
            self, nat_tests, delta_tests, timeout=timeout
        )

        # Load NAT type and delta info.
        # On a server should be open.
        nat = nat_info(nat_type, delta)
        return self.set_nat(nat)

    def set_nat(self, nat: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and store a new NAT info dict on this interface, returning it."""
        if not isinstance(nat, dict):
            raise TypeError("nat must be a dict")
        if nat.keys() != nat_info().keys():
            raise ValueError("nat keys do not match expected schema")
        self.nat = nat
        return nat

    def get_scope_id(self) -> Any:
        """Return the platform-appropriate interface scope identifier (name or numeric index)."""
        if not self.resolved:
            raise ValueError("interface is not resolved")

        # Interface specified by no on windows.
        if platform.system() == "Windows":
            return self.nic_no
        # Other platforms just use the name
        return self.name

    def scope_id_for(self, af: int) -> Any:
        """Return the kernel-level interface index appropriate for af.

        For IPv6 on hosts where the v4 / v6 stacks have separate
        interface index spaces (Windows XP's TCPIP vs TCPIP6 services),
        load_interface captures the v6-side index from netifaces'
        fe80::%scope entry as nic.v6_scope_id. Use that when binding
        or sending on a v6 link-local; fall back to nic.id when the
        stack is unified (Vista+, Linux, etc.) or when v6_scope_id
        wasn't populated.
        """
        if af == IP6 and self.v6_scope_id is not None:
            return self.v6_scope_id
        return self.id

    def nic(self, af: int) -> Optional[str]:
        """Return the NIC IP string for the primary route on this interface for the given address family."""
        # Sanity check.
        if self.resolved:
            if af not in self.what_afs():
                raise ValueError(fstr("address family {0} not supported by this interface", (af,)))
        if self.rp and len(self.rp[af].routes):
            return self.route(af).nic()

    def route(self, af: Optional[int] = None, bind_port: int = 0) -> Any:
        """Return a deep copy of the primary Route for the given address family, raising if none exists."""
        if not self.resolved:
            if af is None:
                raise ValueError("af must be specified when interface is not resolved")

        # Sanity check.
        if self.resolved:
            af = af or self.supported()[0]
            if af not in self.what_afs():
                raise ValueError(fstr("address family {0} not supported by this interface", (af,)))

        # Main route is first.
        if af in self.rp:
            if len(self.rp[af].routes):
                return copy.deepcopy(self.rp[af].routes[0])

        raise LookupError(fstr("No route for {0} found.", (af,)))

    def is_default_patch(self, af: int, gws: Optional[Any] = None) -> bool:
        """Stub that always returns True, used to mark an interface as the default without a real check."""
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
        """Return the sorted list of address families (IP4/IP6) that this interface supports."""
        if not skip_resolve:
            if not self.resolved:
                raise ValueError("interface is not resolved")

        if self.stack == UNKNOWN_STACK:
            raise ValueError("Unknown stack")

        if self.stack == DUEL_STACK:
            return sorted([IP4, IP6])
        return sorted([self.stack])

    def what_afs(self) -> List[int]:
        """Return the address families available on this resolved interface."""
        if not self.resolved:
            raise ValueError("interface is not resolved")
        return self.supported()

    def __await__(self) -> Any:
        return self.start(timeout=self.timeout).__await__()

    def to_dict(self) -> Dict[str, Any]:
        """Serialise this interface to a plain dict suitable for JSON storage or pickling."""
        return nic_to_dict(self)

    @staticmethod
    def get_netifaces() -> Optional[Any]:
        """Return the netifaces module or shim used for interface discovery, or None to use the default."""
        return None

    @staticmethod
    def list() -> List[str]:
        """Return the list of all network interface names known to netifaces."""
        return Interface.get_netifaces().interfaces()

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Interface":
        """Reconstruct an Interface instance from a dict previously produced by to_dict."""
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
        """Resolve the default interface and print the result of an address lookup for google.com."""
        nic = Interface("default")
        d = await Address("google.com", 80, nic)
        print(d)

    async_test(demo_interface)
