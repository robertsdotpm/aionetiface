"""Helper functions for socket binding."""
import asyncio
import platform
from typing import Any, Optional, Tuple
from ...utility.utils import ip_f, MAX_PORT, rand_rang, to_s
from ...net.net_defs import IP4, IP6, IP_PRIVATE, TCP, VALID_ANY_ADDR
from ..ip_range import IPR


def ip6_patch_bind_ip(bind_ip: str, nic_id: Any) -> str:
    """Append the interface scope ID to a link-local IPv6 address for proper binding."""
    # Add interface descriptor if it's link local.
    if nic_id is None:
        return bind_ip
    if to_s(bind_ip[0:2]).lower() in ["fe", "fd"]:
        # Interface specified by no on windows.
        if platform.system() == "Windows":
            try:
                bind_ip = "%s%%%d" % (bind_ip, int(nic_id))
            except (ValueError, TypeError):
                bind_ip = "%s%%%s" % (bind_ip, nic_id)
        else:
            # Other platforms just use the name
            bind_ip = "%s%%%s" % (bind_ip, nic_id)

    return bind_ip


def patch_connect_ip(af: int, ip: str, nic_id: Any, ipr: Optional[Any] = None) -> str:
    """
    When a daemon is bound to the any address you can't just
    use that address to connect to as it's not a valid addr.
    In that case -- rewrite the addr to loopback.
    """
    ipr = ipr or IPR(ip, af=af)
    if ipr.ip in VALID_ANY_ADDR:
        if ipr.af == IP4:
            return "127.0.0.1"
        return "::1"

    # Patch link local addresses.
    if ipr.af == IP6 and ip not in ["::", "::1"]:
        if ipr.is_private:
            return ip6_patch_bind_ip(ip, nic_id)

    return ip


async def get_high_port_socket(
    route: Any, socket_factory: Any, sock_type: int = TCP
) -> Tuple[Any, int]:
    """Bind a socket to a randomly chosen high-numbered port and return (socket, port)."""
    # Minimal config to pass socket factory.
    conf = {"broadcast": False, "linger": None, "sock_proto": 0, "reuse_addr": True}

    # Get a new socket bound to a high order port.
    for i in range(0, 20):
        n = rand_rang(2000, MAX_PORT - 1000)
        await route.bind(n)
        try:
            s = await socket_factory(route, sock_type=sock_type, conf=conf)
        except (OSError, asyncio.TimeoutError):
            continue

        return s, n

    raise OSError("Could not bind high range port.")


"""
Provides an interface that allows for bind() to be called
with its own parameters as a Route object method. Allows
the IP and port used to be accessed inside it as properties.
Otherwise defaults to using IP and port already set in class
which would only be the case if this method were used from a
Bind object and not a Route object. So a lot of hacks here.
But that's the API I wanted.
"""


def bind_closure(self: Any, binder: Any) -> Any:
    """Return an async bind() method that resolves and stores the bind tuple on self."""
    async def bind(port=None, ips=None):
        if self.resolved:
            return

        # Bind parameters.
        port = port or self.bind_port
        ips = ips or self.ips
        if ips is None:
            # Bind parent.
            if hasattr(self, "interface") and self.interface is not None:
                route = self.interface.route(self.af)
                ips = route.nic()
            else:
                # Being inherited from route.
                ips = self.nic()

        # Number or name - platform specific.
        if self.interface is not None:
            nic_id = self.interface.id
        else:
            nic_id = None

        # Get bind tuple for NIC bind.
        self._bind_tups = await binder(af=self.af, ip=ips, port=port, nic_id=nic_id)

        # Save state.
        self.bind_port = port
        self.resolved = True
        return self

    return bind


# Convert compact bind rule list to named access.
class BindRule:
    """Wraps a compact bind-rule list in named attributes for convenient access."""

    def __init__(self, bind_rule: Any) -> None:
        self.platform = bind_rule[0]
        self.af = bind_rule[1]
        self.type = bind_rule[2]
        self.hey = bind_rule[3]
        self.norm = bind_rule[4]
        self.change = bind_rule[5]


# Return a BindRule if it matches the requirements.
def match_bind_rule(
    ip: str, af: int, plat: str, bind_rule: Any, rule_type: Any
) -> Optional["BindRule"]:
    """Return a BindRule instance if the rule matches the given ip, af, platform, and type, else None."""
    bind_rule = BindRule(bind_rule)

    # Skip rule types we're not processing.
    if bind_rule.type != rule_type:
        return

    # Skip address types that don't apply to us.
    if isinstance(bind_rule.af, list):
        if af not in bind_rule.af:
            return
    else:
        if af != bind_rule.af:
            return

    # Skip platform rules that don't match us.
    if bind_rule.platform not in ["*", plat]:
        return

    # Check hey for matches.
    if isinstance(bind_rule.hey, list):
        if ip not in bind_rule.hey:
            return
    if isinstance(bind_rule.hey, int):
        if bind_rule.hey == IP_PRIVATE:
            try:
                ipr = ip_f(ip)
                if not ipr.is_private:
                    return
            except ValueError:
                pass

    return bind_rule
