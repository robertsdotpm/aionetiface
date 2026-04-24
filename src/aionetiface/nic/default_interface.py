"""
TODO: raise exception in .connect if nic.name == default and dest is a link local
theres no actual nic_no stuff this is for simplied programs.
"""

import socket
from typing import Any, Dict
from ..net.net_defs import IP4, IP6
from ..net.net_utils import ip_norm
from ..net.ip_range import IPR
from .route.route import Route
from .route.route_pool import RoutePool
from .interface_utils import get_interface_stack
from .nat.nat_utils import nat_info


def get_default_routes(nic: Any) -> Dict[int, Any]:
    """Probe the OS routing table via UDP connect and return a dict of {af: Route} for reachable families."""
    dests = {IP4: "158.69.27.176", IP6: "2607:5300:0060:80b0:0000:0000:0000:0001"}

    routes = {}
    for af in (
        IP4,
        IP6,
    ):
        dest = (dests[af], 53)  # DNS.

        # create a UDP socket to the host
        try:
            with socket.socket(af, socket.SOCK_DGRAM) as s:
                s.connect(dest)
                nic_ipr = IPR(ip_norm(s.getsockname()[0]), af=af)
                ext_ipr = IPR(dests[af], af=af)
                routes[af] = Route(af, [nic_ipr], [ext_ipr], nic)
        except OSError:
            pass

    return routes


def use_default_interface(nic: Any) -> None:
    """Populate nic with OS-derived default routes so it acts as a generic default interface."""
    nic.name = "default"
    nic.timeout = 4
    nic.netiface_index = 0
    nic.nic_no = 0
    nic.id = None
    nic.mac = ""
    nic.nat = nat_info()
    nic.rp = {IP4: RoutePool(), IP6: RoutePool()}
    routes = get_default_routes(nic)
    for af in routes:
        nic.rp[af] = RoutePool([routes[af]])

    nic.stack = get_interface_stack(nic.rp)
    nic.resolved = True

    def is_default_always(af, gws=None):
        """Always return True to mark this interface as the default for any address family."""
        return True

    nic.is_default = is_default_always
