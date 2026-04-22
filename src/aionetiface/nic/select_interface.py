"""Heuristics for selecting the best NIC for a given connection."""
import asyncio
import platform
from typing import Any, List, Optional, Tuple
from ..utility.utils import fstr, log, log_exception, to_unique
from ..net.net_defs import INTERFACE_UNKNOWN, VALID_AFS
from ..net.ip_range import IPRange
from ..net.net_utils import determine_if_path
from .route.route import Route
from .interface import Interface
from .interface_utils import get_interface_type, log_interface_rp
from ..entrypoint import aionetiface_setup_netifaces


def get_if_by_nic_ipr(nic_ipr: Any, netifaces: Any) -> Optional[Any]:
    for if_name in netifaces.interfaces():
        valid_afs = [netifaces.AF_INET, netifaces.AF_INET6]
        addr_infos = netifaces.ifaddresses(if_name)
        for af in valid_afs:
            if af not in addr_infos:
                continue

            for info in addr_infos[af]:
                needle_ipr = IPRange(info["addr"], bitlen=0)
                if needle_ipr == nic_ipr:
                    i = Interface(if_name)
                    i.netifaces = netifaces
                    i.load_if_info()
                    return i


"""
On a computer that has multiple network interfaces
the right interface needs to be selected depending
on the target destination. The easiest way to do
this is to try connect to the destination without
binding the socket beforehand and checking what
local IP is used for the bind address. The IP will
correspond to a certain network interface which
can be double-checked against what interface is
intended as the source for a connection.
"""


async def select_if_by_dest(
    af: int,
    src_index: int,
    dest_ip: str,
    interface: Any,
    ifs: Optional[List[Any]] = None,
) -> Tuple[Any, int]:
    """
    All valid interfaces for the software can reach
    internet -- use original interface if the dest_ip
    is a public address.
    """
    if ifs is None:
        ifs = []
    host_limit = 0
    dest_ipr = IPRange(dest_ip, bitlen=host_limit)
    if dest_ipr.is_public:
        return interface, src_index

    # Simply connects a non-blocking socket to the dest_ip
    # and checks the local IP used to select an Interface.
    bind_ip = determine_if_path(af, dest_ip)
    bind_ipr = IPRange(bind_ip, bitlen=host_limit)
    bind_interface = get_if_by_nic_ipr(
        bind_ipr,
        interface.netifaces,
    )

    # Unable to find associated interface.
    if bind_interface is None:
        return interface, src_index

    # Auto-selected interface matches chosen interface.
    # Return the chosen interface with no changes.
    if bind_interface.name == interface.name:
        return interface, src_index

    # If already exists return it instead.
    for if_index, needle_if in enumerate(ifs):
        if needle_if.name == bind_interface.name:
            return needle_if, if_index

    return interface, src_index

    # No longer load an IF if its not in their ifs set.
    return await bind_interface

    """
    If the interface that was auto-chosen by the OS
    was different to the one that the caller
    chose then the correct interface is returned.

    Not default is set to force manually choosing
    the interface for sockets as we don't want to
    load all addressing info just to determine
    if its a default interface for the address family.
    """
    bind_interface.is_default = lambda x: False

    """
    Patches the partially loaded interface to have
    a route function that will return a route
    that binds to the correct bind IP. The
    external address is set from the other
    interfaces primary route.
    """
    route = interface.route(af)
    route = Route(af, [bind_ipr], route.ext_ips)
    route.interface = bind_interface

    def route_patch(af):
        return route

    bind_interface.route = route_patch
    return bind_interface


"""
Given a list of interfaces returned from netifaces
or the win_netifaces module this code will filter the list
so that only interfaces that are used for the Internet remain.
Already done in win_netifaces. Uses route tables for Linux and Mac.
Other OS is based on the interface name (not that accurate.)
"""


async def filter_trash_interfaces(netifaces: Optional[Any] = None) -> List[str]:
    netifaces = netifaces or Interface.get_netifaces()
    ifs = netifaces.interfaces()
    os_family = platform.system()

    # Interface list already well filtered by win_netifaces.py.
    if os_family == "Windows":
        return ifs

    # Use route table for these OS family.
    """
    if os_family in ["Linux", "Darwin"]:
        tasks = []
        for if_name in ifs:
            async def worker(if_name):
                r = await is_internet_if(if_name)
                if r:
                    return if_name
                else:
                    return None

            tasks.append(worker(if_name))

        results = await asyncio.gather(*tasks)
        results = strip_none(results)
        
        
        The 'is_interface_if' function depends on using the 'route' binary.
        If it does not exist then the code will fail and return no results.
        In this case default to name-based filtering of netifaces.
        
        if len(results):
            return results
    """

    # Otherwise use the interface type function.
    # Looks at common patterns for interface names (not accurate.)
    clean_ifs = []
    for if_name in ifs:
        if_type = get_interface_type(if_name)
        if if_type != INTERFACE_UNKNOWN:
            clean_ifs.append(if_name)

    return clean_ifs


async def list_interfaces(netifaces: Optional[Any] = None) -> List[str]:
    if netifaces is None:
        netifaces = await aionetiface_setup_netifaces()

    # Get list of good interfaces with ::/0 or 0.0.0.0 routes.
    ifs = await filter_trash_interfaces(netifaces)
    ifs = to_unique(ifs)
    if ifs == []:
        # Something must have gone wrong so just use regular netifaces.
        ifs = netifaces.interfaces()

    ifs = sorted(ifs)
    return ifs

    # Start all interfaces.
    if_list = []
    tasks = []
    for if_name in ifs:
        if_info = str(netifaces.ifaddresses(if_name))
        log(fstr("Attempt to start if name {0}", (if_name,)))
        log(fstr("Net iface results for that if = {0}", (if_info,)))

        async def worker(if_name):
            try:
                interface = await Interface(if_name, netifaces=netifaces).start()
                try:
                    if load_nat:
                        await interface.load_nat()
                except (OSError, asyncio.TimeoutError):
                    log("Failed to load nat for interface.")
                    # Just use the default NAT info.

                if_list.append(interface)
            except (OSError, asyncio.TimeoutError):
                log_exception()
                return

        tasks.append(
            # Assume timeout = non-routable.
            worker(if_name)
        )

    await asyncio.gather(*tasks)

    # Filter any interfaces that have no routes.
    # This will filter out loopback and other crap interfaces.
    good_ifs = []
    for interface in if_list:
        for af in VALID_AFS:
            if len(interface.rp[af].routes):
                good_ifs.append(interface)
                break

    # Log interfaces and routes.
    log("> Loaded interfaces.")
    for if_no, interface in enumerate(good_ifs):
        log(fstr("> Routes for interface {0}:", (if_no,)))
        log_interface_rp(interface)

    return good_ifs
