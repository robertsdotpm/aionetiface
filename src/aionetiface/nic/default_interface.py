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
    dests = {IP4: "8.8.8.8", IP6: "2001:4860:4860::8888"}

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
        return True

    nic.is_default = is_default_always
