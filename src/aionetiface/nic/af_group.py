"""AFGroup -- per-AF Interface selection.

Most clients (Router, MQTT, SmartPipe, Address, ...) historically took
a single Interface and assumed it was workable for both v4 and v6.
That assumption breaks the moment a host has different NICs handling
different AFs:

  * Mobile dongle is v4-only CGNAT (the actual NAT-traversal target);
    primary NIC is dual-stack -- v4 brokers must go via mobile, v6
    brokers via primary.
  * Test VMs with v6 disabled on one NIC but enabled on another.
  * Multi-homed hosts with management-only v4 and services-only v6.

AFGroup is a thin wrapper around {af: Interface} that

  * accepts a single dual-stack Interface and fans it across the AFs
    that interface supports (legacy compat -- pass a single iface,
    everything still works);
  * accepts an explicit dict so multi-homed callers can split AFs
    across NICs;
  * validates per-AF support at construction so a "this NIC doesn't
    actually have v6" mistake is caught at the boundary instead of as
    a NoneType error three layers deep;
  * exposes for_af / supports / iteration so consuming code never
    reaches into a raw dict.
"""

from ..utility.utils import fstr
from .interface import Interface


class AFGroup:
    """The set of Interfaces a client uses, keyed by address family."""

    def __init__(
        self,
        interfaces,
    ):
        """Build the group from another AFGroup, a {af: Interface} dict, or a single Interface."""
        by_af = {}
        if isinstance(interfaces, AFGroup):
            by_af = dict(interfaces.by_af)
        elif isinstance(interfaces, dict):
            for af, iface in interfaces.items():
                if iface is None:
                    raise ValueError(
                        fstr("AFGroup: interface for af {0} is None", (af,))
                    )
                if af not in iface.what_afs():
                    raise ValueError(fstr(
                        "AFGroup: interface {0} does not support af {1}",
                        (repr(iface.name), af),
                    ))
                by_af[af] = iface
        elif isinstance(interfaces, Interface):
            for af in interfaces.what_afs():
                by_af[af] = interfaces
        else:
            raise TypeError(fstr(
                "AFGroup: expected Interface, dict, or AFGroup; got {0}",
                (repr(type(interfaces).__name__),),
            ))

        self.by_af = by_af

    def for_af(self, af):
        """Return the Interface assigned to *af*; raise KeyError if none."""
        if af not in self.by_af:
            raise KeyError(
                fstr("AFGroup: no interface configured for af {0}", (af,))
            )
        return self.by_af[af]

    def get(self, af, default=None):
        """Return the Interface for *af*, or *default* when none is configured."""
        return self.by_af.get(af, default)

    def supports(self, af):
        """True iff this group has an Interface configured for *af*."""
        return af in self.by_af

    def afs(self):
        """Return the address families this group covers, in insertion order."""
        return list(self.by_af.keys())

    # ------------------------------------------------------------------
    # Interface-mimic API
    #
    # These mirror the per-AF accessors on Interface so AFGroup is a
    # drop-in replacement in callers that previously took an Interface.
    # The Interface methods that take an *implicit* primary AF (zero-arg
    # `route()` / `nic()`) are intentionally NOT mirrored -- AFGroup has
    # no single primary by definition; callers that used those forms
    # need to pass an explicit `af`. The compiler / runtime will catch
    # the missing-arg call sites cleanly.
    # ------------------------------------------------------------------

    def route(self, af, bind_port=0):
        """Return the primary Route on the Interface chosen for *af*."""
        return self.for_af(af).route(af, bind_port)

    def nic(self, af):
        """Return the NIC IP string for the Interface chosen for *af*."""
        return self.for_af(af).nic(af)

    def supported(self, skip_resolve=0):
        """Return the AFs this group covers (matches Interface.supported's signature)."""
        return self.afs()

    def what_afs(self):
        """Alias for supported(); matches Interface.what_afs."""
        return self.afs()

    def is_default(self, af, gws=None):
        """Return whether the Interface chosen for *af* is the host's default route."""
        return self.for_af(af).is_default(af, gws)

    @classmethod
    def from_interfaces(cls, interfaces):
        """Build an AFGroup from a list of Interfaces, picking first-match per AF.

        Walks *interfaces* in order; for each AF, the first interface that
        supports it wins. Lets a caller express simple per-AF preferences
        purely by NIC ordering -- e.g. pass [mobile_v4_only, primary_dual]
        and the v4 path uses the mobile NIC while the v6 path uses primary.
        Callers that want a different mapping (or to skip an AF entirely)
        should construct AFGroup with an explicit dict instead.
        """
        if not interfaces:
            raise ValueError("AFGroup.from_interfaces: empty interfaces list")
        by_af = {}
        for iface in interfaces:
            for af in iface.what_afs():
                if af not in by_af:
                    by_af[af] = iface
        if not by_af:
            raise ValueError("AFGroup.from_interfaces: no AF coverage across given interfaces")
        return cls(by_af)

    def interfaces(self):
        """Return the unique Interfaces in this group (deduped, insertion order)."""
        seen = []
        for iface in self.by_af.values():
            if iface not in seen:
                seen.append(iface)
        return seen

    def __iter__(self):
        return iter(self.by_af.items())

    def __len__(self):
        return len(self.by_af)

    def __contains__(self, af):
        return af in self.by_af

    def __repr__(self):
        body = ", ".join(
            "{0}: {1!r}".format(af, iface.name)
            for af, iface in self.by_af.items()
        )
        return "AFGroup({" + body + "})"
