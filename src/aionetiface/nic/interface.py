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
import pprint
import socket
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
        name=None,
        stack=DUEL_STACK,
        nat=None,
        netifaces=None,
        timeout=4,
    ):
        super().__init__()
        if name == "default":
            use_default_interface(self)
            return

        # Otherwise load everything.
        self.resolved = False
        self.netiface_index = None
        self.id = self.mac = self.nic_no = None
        # nat starts as None to make "never tested" distinguishable from
        # any real classification result. Callers that need a value before
        # load_nat completes must apply their own default explicitly --
        # auto-defaulting to nat_info() (symmetric+random) hid load_nat
        # failures because the un-tested state collided with the worst
        # real result. set_nat() writes here once classification finishes.
        self.nat = nat
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
        netifaces=None,
        min_agree=2,
        max_agree=5,
        timeout=4,
    ):
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
        self, nat_tests=5, delta_tests=12, timeout=4
    ):
        """Run NAT type and port-delta tests for this interface and store the results, returning the nat dict."""
        # Try main decentralized NAT test approach.
        nat_type, delta = await nic_load_nat(
            self, nat_tests, delta_tests, timeout=timeout
        )

        # Load NAT type and delta info.
        # On a server should be open.
        nat = nat_info(nat_type, delta)
        return self.set_nat(nat)

    def set_nat(self, nat):
        """Validate and store a new NAT info dict on this interface, returning it."""
        if not isinstance(nat, dict):
            raise TypeError("nat must be a dict")
        if nat.keys() != nat_info().keys():
            raise ValueError("nat keys do not match expected schema")
        self.nat = nat
        return nat

    def get_nic_id(self, af=None):
        """Return the kernel-level interface index for af.

        Defers to the netifaces backend's get_nic_id when present
        (Windows shim, fallback shim, test shim). For PyPI netifaces
        on POSIX -- which has no get_nic_id -- parse the %scope
        token off a link-local entry in ifaddresses for af=IP6, and
        otherwise return the interface name (POSIX uses names as
        scope ids and the kernel accepts them in fe80::%scope
        directly).

        The "default" pseudo-interface (use_default_interface) skips
        Interface.__init__'s normal body via early-return, so
        self.netifaces is *unset* (not just None) -- guard with
        getattr so the lookup doesn't AttributeError. Default has no
        kernel ifindex of its own; return self.id (None for the
        default) to match the pre-refactor behaviour.
        """
        nf = getattr(self, "netifaces", None)
        if nf is None:
            return getattr(self, "id", None)
        if hasattr(nf, "get_nic_id"):
            return nf.get_nic_id(af, self.name)
        try:
            return socket.if_nametoindex(self.name)
        except (OSError, AttributeError):
            pass
        if af == IP6:
            try:
                addrs = nf.ifaddresses(self.name).get(IP6, [])
            except (KeyError, OSError, ValueError):
                addrs = []
            for entry in addrs:
                addr = entry.get("addr", "")
                if "%" in addr:
                    return addr.rsplit("%", 1)[1]
        return self.name

    def nic(self, af):
        """Return the NIC IP string for the primary route on this interface for the given address family."""
        # Sanity check.
        if self.resolved:
            if af not in self.what_afs():
                raise ValueError(fstr("address family {0} not supported by this interface", (af,)))
        if self.rp and len(self.rp[af].routes):
            return self.route(af).nic()

    def route(self, af=None, bind_port=0):
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

    def is_default_patch(self, af, gws=None):
        """Stub that always returns True, used to mark an interface as the default without a real check."""
        return True

    def is_default(self, af, gws=None):
        """
        Return True if this interface is the default route for address family af.

        Accepting a gateway list (gws) avoids a repeated system call, at the
        cost of stale results if the routing table changes (e.g. wifi disconnect)
        while the list is held.
        """
        return is_nic_default(self, af, gws)

    def supported(self, skip_resolve=0):
        """Return the sorted list of address families (IP4/IP6) that this interface supports."""
        if not skip_resolve:
            if not self.resolved:
                raise ValueError("interface is not resolved")

        if self.stack == UNKNOWN_STACK:
            raise ValueError("Unknown stack")

        if self.stack == DUEL_STACK:
            return sorted([IP4, IP6])
        return sorted([self.stack])

    def what_afs(self):
        """Return the address families available on this resolved interface."""
        if not self.resolved:
            raise ValueError("interface is not resolved")
        return self.supported()

    def __await__(self):
        return self.start(timeout=self.timeout).__await__()

    def to_dict(self):
        """Serialise this interface to a plain dict suitable for JSON storage or pickling."""
        return nic_to_dict(self)

    @staticmethod
    def get_netifaces():
        """Return the netifaces module or shim used for interface discovery, or None to use the default."""
        return None

    @staticmethod
    def list():
        """Return the list of all network interface names known to netifaces."""
        return Interface.get_netifaces().interfaces()

    @staticmethod
    def from_dict(d):
        """Reconstruct an Interface instance from a dict previously produced by to_dict."""
        return nic_from_dict(d, Interface)

    # Make this interface printable because it's useful.
    def __str__(self):
        return pprint.pformat(self.to_dict())

    # Show a representation of this object.
    def __repr__(self):
        nic_info = str(self)
        return "Interface.from_dict(%s)" % (nic_info)

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    # Make all nic IPs across route pools a generator.
    # Return both the nic_ipr and route they belong to.
    def __iter__(self):
        seen = set()
        for af in (IP4, IP6):
            for route in self.rp[af]:
                for nic_ipr in route.nic_ips + route.link_locals:
                    if nic_ipr not in seen:
                        nic_ipr.route = route
                        seen.add(nic_ipr)
                        yield nic_ipr


if __name__ == "__main__":  # pragma: no cover

    async def demo_interface():
        """Resolve the default interface and print the result of an address lookup for google.com."""
        nic = Interface("default")
        d = await Address("google.com", 80, nic)
        print(d)

    async_test(demo_interface)
