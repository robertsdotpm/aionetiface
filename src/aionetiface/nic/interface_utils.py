import asyncio
import re
import socket
from functools import lru_cache
from typing import Any, Dict, List, Optional
from ..utility.utils import async_wrap_errors, fstr, log, log_exception, to_s
from ..errors import InterfaceInvalidAF, InterfaceNotFound
from ..net.net_defs import (
    BLACK_HOLE_IPS,
    DUEL_STACK,
    INTERFACE_ETHERNET,
    INTERFACE_UNKNOWN,
    INTERFACE_WIRELESS,
    IP4,
    IP6,
    UNKNOWN_STACK,
    VALID_AFS,
)
from .netifaces.netiface_extra import af_to_netiface, netiface_gateways
from .nat.nat_utils import nat_info
from .route.route_pool import RoutePool
from ..utility.var_names import TXT


def get_interface_af(netifaces: Any, name: str) -> int:
    af_list = []
    for af in [IP4, IP6]:
        if af not in netifaces.ifaddresses(name):
            continue

        if len(netifaces.ifaddresses(name)[af]):
            af_list.append(af)

    if len(af_list) == 2:
        return DUEL_STACK

    if len(af_list) == 1:
        return af_list[0]

    return UNKNOWN_STACK


@lru_cache(maxsize=None)
def get_default_nic_ip(af: int) -> str:
    af = int(af)
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.connect((BLACK_HOLE_IPS[af], 80))
            name = s.getsockname()[0]
            s.close()
            return name
    except OSError:
        log_exception()
        return ""


def get_default_iface(
    netifaces: Any,
    afs: List[int] = VALID_AFS,
    exp: int = 1,
    duel_stack_test: bool = True,
) -> str:
    for af in afs:
        af = int(af)
        nic_ip = get_default_nic_ip(af)
        for if_name in netifaces.interfaces():
            addr_infos = netifaces.ifaddresses(if_name)
            if af not in addr_infos:
                continue

            for addr_info in addr_infos[af]:
                if addr_info["addr"] == nic_ip:
                    return if_name

    return ""


def get_interface_type(name: str) -> int:
    name = name.lower()
    if re.match(r"en[0-9]+", name) is not None:
        return INTERFACE_ETHERNET

    eth_names = ["eth", "eno", "ens", "enp", "enx", "ethernet"]
    for eth_name in eth_names:
        if eth_name in name:
            return INTERFACE_ETHERNET

    wlan_names = ["wlx", "wlp", "wireless", "wlan", "wifi"]
    for wlan_name in wlan_names:
        if wlan_name in name:
            return INTERFACE_WIRELESS

    if "wl" == name[0:2]:
        return INTERFACE_WIRELESS

    return INTERFACE_UNKNOWN


def get_interface_stack(rp: Dict[int, Any]) -> int:
    stacks = []
    for af in [IP4, IP6]:
        if af in rp:
            if len(rp[af].routes):
                stacks.append(af)

    if len(stacks) == 2:
        return DUEL_STACK

    if len(stacks):
        return stacks[0]

    return UNKNOWN_STACK


def clean_if_list(ifs: List[str]) -> List[str]:
    # Otherwise use the interface type function.
    # Looks at common patterns for interface names (not accurate.)
    clean_ifs = []
    for if_name in ifs:
        if_type = get_interface_type(if_name)
        if if_type != INTERFACE_UNKNOWN:
            clean_ifs.append(if_name)

    return clean_ifs


def log_interface_rp(interface: Any) -> None:
    for af in VALID_AFS:
        if not len(interface.rp[af].routes):
            continue

        route_s = str(interface.rp[af].routes)
        log(
            fstr(
                "> AF {0} = {1}",
                (
                    af,
                    route_s,
                ),
            )
        )
        log(fstr("> nic() = {0}", (interface.route(af).nic(),)))
        log(fstr("> ext() = {0}", (interface.route(af).ext(),)))


def get_ifs_by_af_intersect(if_list: List[Any]) -> List[Any]:
    largest = []
    af_used = None
    for af in VALID_AFS:
        hay = []
        for iface in if_list:
            if af in iface.supported():
                hay.append(iface)

        if len(hay) > len(largest):
            largest = hay
            af_used = af

    return [largest, af_used]


def is_nic_default(nic: Any, af: int, gws: Optional[Any] = None) -> bool:
    def try_netiface_check(af, gws):
        af = af_to_netiface(af)
        if not gws:
            gws = netiface_gateways(nic.netifaces, get_interface_type, preference=af)

        def_gws = gws["default"]
        if af not in def_gws:
            return False
        else:
            info = def_gws[af]
            if info[1] == nic.name:
                return True
            else:
                return False

    def try_sock_trick(af):
        if_name = get_default_iface(nic.netifaces, afs=[af])
        if if_name == "":
            return False

        return nic.name == if_name

    try:
        ret = try_sock_trick(af) or try_netiface_check(af, gws)
        return ret
    except (OSError, KeyError, AttributeError):
        log_exception()
        return False


def nic_from_dict(d: Dict[str, Any], Interface: Any) -> Any:
    i = Interface(d["name"])
    i.netiface_index = d["netiface_index"]
    i.nic_no = d["nic_no"]
    i.id = d["id"]
    i.mac = d["mac"]

    i.is_default = lambda af, gws=None: d["is_default"][af]

    # Set the interface route pool.
    i.rp = {
        IP4: RoutePool.from_dict(d["rp"][int(IP4)]),
        IP6: RoutePool.from_dict(d["rp"][int(IP6)]),
    }

    # Set interface part of routes.
    for af in VALID_AFS:
        for route in i.rp[af].routes:
            route.interface = i

    # Set NAT details.
    i.nat = nat_info(d["nat"]["type"], d["nat"]["delta"])

    # Set stack type of the interface based on the route pool.
    i.stack = get_interface_stack(i.rp)

    # Indicate the interface is fully resolved.
    i.resolved = True

    # ... and return it.
    return i


def nic_to_dict(nic: Any) -> Dict[str, Any]:
    return {
        "netiface_index": nic.netiface_index,
        "name": nic.name,
        "nic_no": nic.nic_no,
        "id": nic.id,
        "mac": nic.mac,
        "is_default": {
            int(IP4): nic.is_default(IP4, None),
            int(IP6): nic.is_default(IP6, None),
        },
        "nat": {
            "type": nic.nat["type"],
            "nat_info": TXT["nat"][nic.nat["type"]],
            "delta": nic.nat["delta"],
            "delta_info": TXT["delta"][nic.nat["delta"]["type"]],
        },
        "rp": {int(IP4): nic.rp[IP4].to_dict(), int(IP6): nic.rp[IP6].to_dict()},
    }


# Given a list of Interface dicts.
# Convert them back to Interfaces and return a list.
def dict_to_if_list(dict_list: List[Dict[str, Any]], Interface: Any) -> List[Any]:
    if_list = []
    for d in dict_list:
        interface = Interface.from_dict(d)
        if_list.append(interface)

    return if_list


# Given a list of Interface objs.
# Convert to dict and return a list.
def if_list_to_dict(if_list: List[Any]) -> List[Dict[str, Any]]:
    dict_list = []
    for interface in if_list:
        d = interface.to_dict()
        dict_list.append(d)

    return dict_list


async def load_interfaces(
    if_names: List[Any],
    Interface: Any,
    min_agree: int = 2,
    max_agree: int = 5,
    skip_nat: bool = False,
    timeout: int = 4,
) -> List[Any]:
    """
    When an interface is loaded, it is placed into a clearing queue.
    The event loop cycles through this queue, switching between tasks as they
    become eligible to run. Because completion time depends on how many other
    interfaces are also pending, timeouts are set relative to the total number of
    active interfaces rather than per task in isolation. This ensures that delays from
    other tasks are accounted for and no single timeout is miscalculated by
    assuming immediate execution.
    """
    nics = []
    for if_name in if_names:
        try:
            nic = Interface(if_name)
            await nic.start(
                min_agree=min_agree,
                max_agree=max_agree,
                timeout=timeout,
            )

            if not skip_nat:
                nat = await async_wrap_errors(nic.load_nat(timeout=timeout))

                if nat is None:
                    log("Could not load NAT for " + to_s(if_name))

            nics.append(nic)
        except asyncio.CancelledError:
            raise
        except (OSError, asyncio.TimeoutError, InterfaceNotFound, InterfaceInvalidAF):
            log_exception()

    return nics


def get_nic_for_af(nic_list: List[Any]) -> Dict[int, Optional[Any]]:
    ret = {IP4: None, IP6: None}
    for af in (IP4, IP6):
        for nic in nic_list:
            if af in nic.supported():
                ret[af] = nic
                break

    return ret
