"""Utility functions for route selection and interface mapping."""
import asyncio
import copy
from functools import cmp_to_key
from ...net.net_defs import VALID_AFS
from ...net.ip_range import IPRange
from ..netifaces.netiface_extra import af_to_netiface, netiface_addr_to_ipr
from ...net.bind.bind import Bind
from .route import Route
from .route_pool import RoutePool


"""
As there's only one STUN server in the preview release the
consensus code is not needed.
"""
ROUTE_CONSENSUS = [1, 1]


def rp_from_fixed(fixed, interface, af):  # pragma: no cover
    """
    [
        [
            nics [[ip, opt netmask], ...],
            exts [[ip]]
        ],
        route ...
    ]
    """

    routes = []
    for route in fixed:
        nic_iprs = []
        ext_iprs = []
        for meta in [[nic_iprs, route[0]], [ext_iprs, route[1]]]:
            dest, nic_infos = meta
            for nic_info in nic_infos:
                ip = nic_info[0]
                netmask = None
                if len(nic_info) == 2:
                    netmask = nic_info[1]

                ipr = IPRange(ip, netmask=netmask)
                dest.append(ipr)

        route = Route(af, nic_iprs, ext_iprs, interface)
        routes.append(route)

    return RoutePool(routes)


async def get_nic_iprs(af, interface, netifaces):
    tasks = []
    if netifaces is None:
        return []
    netifaces_af = af_to_netiface(af)
    if_addresses = netifaces.ifaddresses(interface.name)
    if netifaces_af in if_addresses:
        bound_addresses = if_addresses[netifaces_af]
        for info in bound_addresses:
            # Only because it calls getaddrinfo is it async.
            task = netiface_addr_to_ipr(af, interface.id, info)

            tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r is not None and not isinstance(r, Exception)]


def sort_routes(routes):
    """Return a deterministically ordered copy of routes sorted by external IP."""
    # Deterministically order routes list.
    def cmp(r1, r2):
        """Return a numeric comparison value between two routes based on their first external IP."""
        return int(r1.ext_ips[0]) - int(r2.ext_ips[0])

    return sorted(routes, key=cmp_to_key(cmp))


def get_route_by_src(src_ip, results):
    """Return the route from results whose source IP matches src_ip, or None if not found."""
    route = [y for x, y in results if x == src_ip]
    if len(route):
        route = route[0]
    else:
        route = None

    return route


def exclude_routes_by_src(
    src_ips, results
):
    """Return routes from results whose source IP is not present in src_ips."""
    new_list = []
    for src_ip, route in results:
        found_src = False
        for needle_ip in src_ips:
            if src_ip == needle_ip:
                found_src = True

        if not found_src:
            new_list.append(route)

    return new_list


# Combine all routes from interface into RoutePool.
def interfaces_to_rp(interface_list):
    """Return an AF-keyed RoutePool dict built by merging routes from all interfaces."""
    rp = {}
    for af in VALID_AFS:
        route_lists = []
        for iface in interface_list:
            if af not in iface.rp:
                continue

            route_lists.append(copy.deepcopy(iface.rp[af].routes))

        routes = sum(route_lists, [])
        rp[af] = RoutePool(routes)

    return rp


# Converts a Bind object to a Route.
# Interface for bind object may be None if it's loopback.
async def bind_to_route(bind_obj):
    if not isinstance(bind_obj, Bind):
        raise TypeError("Invalid obj type passed to bind_to_route.")

    """
    nic_bind = 1 -- ipv4 nic or ipv6 link local
    ext_bind = 2 -- ipv4 external wan ip / ipv6 global ip
        black hole ip if called with no ips start_local

    ips = both set to ips value
    nic_bind or ext_bind based on dest address in sock_factory
    """
    assert bind_obj.resolved
    interface = bind_obj.interface
    nic_bind = ext_bind = bind_obj._bind_tups[0]
    af = bind_obj.af
    assert interface.resolved

    """
    If the ext_bind contains a valid public address then
    use this directly for the ext_ipr in the Route obj.
    Otherwise attempt to find a pre-existing route in
    the Interface route pool that has the same nic_bind
    and use it's associated ext_ipr.
    """
    ext_set = 0
    nic_ipr = IPRange(nic_bind)
    ext_ipr = IPRange(ext_bind)
    if not ext_ipr.is_public:
        if interface is not None:
            # Check all routes for a matching NIC IPR.
            for hey_route in interface.rp[af].routes:
                # Check all NIC IPRs.
                for nic_hey in hey_route.nic_ips:
                    # NIC IPR found in the route entries.
                    # Use the routes EXT.
                    if nic_ipr in nic_hey:
                        ext_ipr = hey_route.ext_ips[0]
                        ext_ipr = copy.deepcopy(ext_ipr)
                        ext_set = 1
                        break

                if ext_set:
                    break

    # Build route object.
    route = Route(
        af=af, nic_ips=[nic_ipr], ext_ips=[ext_ipr], interface=interface, ext_check=0
    )

    # Bind to port in route.
    await route.bind(port=bind_obj.bind_port)
    return route


