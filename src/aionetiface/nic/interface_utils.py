"""Helper functions for network interface discovery and filtering."""
import asyncio
import re
import socket
import time
from functools import lru_cache
from ..utility.utils import fstr, log, log_exception, to_s
from ..errors import ErrorCantLoadNATInfo, InterfaceInvalidAF, InterfaceNotFound
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


def get_interface_af(netifaces, name):
    """Return the address-family stack constant (DUEL_STACK, IP4, IP6, or UNKNOWN_STACK) for interface name."""
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
def get_default_nic_ip(af):
    """Return the local IP address the OS would use to reach the internet for the given address family."""
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
    netifaces,
    afs=None,
    exp=1,
    duel_stack_test=True,
):
    """Return the interface name whose address matches the OS-selected source IP, or an empty string if none found."""
    if afs is None:
        afs = VALID_AFS
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


def get_interface_type(name):
    """Classify a network interface name as INTERFACE_ETHERNET, INTERFACE_WIRELESS, or INTERFACE_UNKNOWN."""
    name = name.lower()
    if re.match(r"en[0-9]+", name) is not None:
        return INTERFACE_ETHERNET

    eth_names = ["eth", "eno", "ens", "enp", "enx", "ethernet", "local area connection"]
    for eth_name in eth_names:
        if eth_name in name:
            return INTERFACE_ETHERNET

    wlan_names = ["wlx", "wlp", "wireless", "wlan", "wifi", "wireless network connection"]
    for wlan_name in wlan_names:
        if wlan_name in name:
            return INTERFACE_WIRELESS

    if "wl" == name[0:2]:
        return INTERFACE_WIRELESS

    return INTERFACE_UNKNOWN


def get_interface_stack(rp):
    """Derive the stack constant (DUEL_STACK, single AF, or UNKNOWN_STACK) from a route-pool dict."""
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


def clean_if_list(ifs):
    """Filter an interface name list to only those with a recognised type (ethernet or wireless)."""
    # Otherwise use the interface type function.
    # Looks at common patterns for interface names (not accurate.)
    clean_ifs = []
    for if_name in ifs:
        if_type = get_interface_type(if_name)
        if if_type != INTERFACE_UNKNOWN:
            clean_ifs.append(if_name)

    return clean_ifs


def log_interface_rp(interface):
    """Log the route pool, NIC IP, and external IP for each address family on the given interface."""
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


def get_ifs_by_af_intersect(if_list):
    """Return the [interfaces, af] pair where af is the address family with the most supporting interfaces."""
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


def is_nic_default(nic, af, gws=None):
    """Return True if nic owns the IP the OS would pick for outbound traffic on af.

    Cross-platform: a single ``Interface("default")`` is constructed lazily and
    cached on the Interface class. Its routes are populated via the UDP-connect
    trick (see ``default_interface.get_default_routes``) which asks the kernel
    directly which source IP it would use for an arbitrary external destination.
    We then compare that IP against the addresses netifaces reports for ``nic``.
    Multi-NIC hosts work naturally — only one NIC owns the source IP, so only
    one returns True per AF. The ``gws`` argument is accepted for API
    compatibility but ignored.
    """
    # Deferred import: interface_utils is imported by interface.py.
    from .interface import Interface  # noqa: F401  pylint: disable=import-outside-toplevel

    if Interface.default is None:
        try:
            Interface.default = Interface("default")
        except OSError:
            log_exception()
            return False

    default = Interface.default
    try:
        default_ip = default.rp[af].routes[0].nic()
    except (KeyError, IndexError, AttributeError, LookupError):
        return False

    if not getattr(nic, "netifaces", None) or not getattr(nic, "name", None):
        return False

    try:
        addrs = nic.netifaces.ifaddresses(nic.name).get(int(af), [])
    except (KeyError, ValueError, OSError):
        log_exception()
        return False

    for addr in addrs:
        ip = addr.get("addr", "")
        if not ip:
            continue
        # Strip IPv6 scope id (e.g. "fe80::1%eth0").
        ip = ip.split("%", 1)[0]
        if ip == default_ip:
            return True

    return False


def nic_from_dict(d, Interface):
    """Reconstruct an Interface object from a serialised dict, restoring routes, NAT info, and stack type."""
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

    # Set NAT details. Older or partial dicts may have nat=None when the
    # source interface never completed classification; preserve that.
    nat_d = d.get("nat")
    if nat_d is None:
        i.nat = None
    else:
        i.nat = nat_info(nat_d["type"], nat_d["delta"])

    # Set stack type of the interface based on the route pool.
    i.stack = get_interface_stack(i.rp)

    # Indicate the interface is fully resolved.
    i.resolved = True

    # ... and return it.
    return i


def nic_to_dict(nic):
    """Serialise a NIC interface object to a plain dict, including route pools, NAT info, and default flags."""
    if nic.nat is not None:
        nat_dict = {
            "type": nic.nat["type"],
            "nat_info": TXT["nat"][nic.nat["type"]],
            "delta": nic.nat["delta"],
            "delta_info": TXT["delta"][nic.nat["delta"]["type"]],
        }
    else:
        nat_dict = None
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
        "nat": nat_dict,
        "rp": {int(IP4): nic.rp[IP4].to_dict(), int(IP6): nic.rp[IP6].to_dict()},
    }


# Given a list of Interface dicts.
# Convert them back to Interfaces and return a list.
def dict_to_if_list(dict_list, Interface):
    """Convert a list of interface dicts back into Interface objects and return them as a list."""
    if_list = []
    for d in dict_list:
        interface = Interface.from_dict(d)
        if_list.append(interface)

    return if_list


# Given a list of Interface objs.
# Convert to dict and return a list.
def if_list_to_dict(if_list):
    """Convert a list of Interface objects to a list of serialised dicts."""
    dict_list = []
    for interface in if_list:
        d = interface.to_dict()
        dict_list.append(d)

    return dict_list


async def load_interfaces(
    if_names,
    Interface,
    min_agree=2,
    max_agree=5,
    skip_nat=False,
    timeout=4,
):
    """
    Load every NIC concurrently with a per-NIC wall-clock cap.

    Sequential loading was the historical shape, but on hosts with a
    pile of fake / virtual adapters (Windows 11 Hyper-V switches, WSL
    bridges, leftover loopback drivers) one NIC's STUN probe sitting
    on its full ``timeout`` budget would block every NIC behind it.
    A 30-fake-adapter machine could spend 4 minutes here before the
    real interfaces ever got probed, and `Node.start()` would tip
    over the test runner's 300s SIGKILL budget.

    Now each NIC's (start + load_nat) runs as an independent task
    via ``asyncio.gather`` with bounded concurrency, and each phase
    has its own ``asyncio.wait_for`` budget so a slow ``nic.start``
    can't eat the budget that ``nic.load_nat`` was supposed to use.
    A failed load_nat is logged loudly and ``nic.nat`` stays at
    ``None`` (the constructor default) so callers can tell the
    difference between a real classification and an un-tested NIC.
    """
    # Two separate phases, each with its own deadline. Older code shared
    # one (2*timeout)+1 budget across both phases, which on slow hosts
    # (Windows XP especially) let nic.start eat enough of the budget
    # that nic.load_nat got cancelled mid-probe -- silently leaving the
    # NIC's nat at the un-tested default. Splitting eliminates the
    # starvation; each phase gets a small slack over its own inner
    # timeout. nic_load_nat already wraps fast_nat_test and delta_test
    # in async_wrap_errors(timeout=timeout) running in parallel, so the
    # legitimate ceiling is ~timeout + setup overhead.
    start_cap = max(timeout, 4) + 2
    nat_cap = max(timeout, 4) + 2

    # Bounded concurrency. Pure unlimited gather() turned out to be
    # unreliable on Windows: nic.start / nic.load_nat shell out to
    # netsh / wmic / powershell, and firing 30 of those at once
    # exhibits intermittent failures. A small semaphore keeps the
    # shellouts orderly while still letting the slow STUN probes on
    # multiple NICs overlap, which is where the real wall-clock win
    # comes from.
    LOAD_CONCURRENCY = 4
    sem = asyncio.Semaphore(LOAD_CONCURRENCY)

    async def load_one(if_name):
        async with sem:
            t0 = time.time()
            log("[IFLOAD] enter nic={0} start_cap={1}s nat_cap={2}s timeout={3}s skip_nat={4}".format(
                to_s(if_name), start_cap, nat_cap, timeout, skip_nat,
            ))
            try:
                nic = Interface(if_name)

                # Phase 1: nic.start. Has its own budget so a slow
                # external-IP probe cannot starve the NAT classifier.
                log("[IFLOAD]   nic={0} calling nic.start (cap={1}s)".format(
                    to_s(if_name), start_cap,
                ))
                t1 = time.time()
                try:
                    await asyncio.wait_for(
                        nic.start(
                            min_agree=min_agree,
                            max_agree=max_agree,
                            timeout=timeout,
                        ),
                        timeout=start_cap,
                    )
                except asyncio.TimeoutError:
                    log("[IFLOAD] FAIL  nic={0} nic.start TIMED OUT after {1:.2f}s (cap={2}s)".format(
                        to_s(if_name), time.time() - t1, start_cap,
                    ))
                    raise
                log("[IFLOAD]   nic={0} nic.start OK ({1:.2f}s)".format(
                    to_s(if_name), time.time() - t1,
                ))

                # Phase 2: nic.load_nat. Independent budget. We DO NOT
                # use async_wrap_errors here because that swallowed the
                # cancellation/exception silently and left nic.nat at
                # the constructor default -- producing a classification
                # that looked real but wasn't. Catch the specific
                # exceptions we know about and log loudly instead, so
                # an un-tested NIC is unmistakable in the log.
                if not skip_nat:
                    log("[IFLOAD]   nic={0} calling load_nat (cap={1}s)".format(
                        to_s(if_name), nat_cap,
                    ))
                    t2 = time.time()
                    try:
                        await asyncio.wait_for(
                            nic.load_nat(timeout=timeout),
                            timeout=nat_cap,
                        )
                        log("[IFLOAD]   nic={0} load_nat OK ({1:.2f}s) nat={2}".format(
                            to_s(if_name), time.time() - t2, nic.nat,
                        ))
                    except asyncio.TimeoutError:
                        log("[IFLOAD] WARN  nic={0} load_nat TIMED OUT after {1:.2f}s (cap={2}s); nic.nat stays None".format(
                            to_s(if_name), time.time() - t2, nat_cap,
                        ))
                    except ErrorCantLoadNATInfo as e:
                        log("[IFLOAD] WARN  nic={0} load_nat raised ErrorCantLoadNATInfo: {1}; nic.nat stays None".format(
                            to_s(if_name), e,
                        ))
                    except (OSError, ConnectionError) as e:
                        log("[IFLOAD] WARN  nic={0} load_nat raised {1}: {2}; nic.nat stays None".format(
                            to_s(if_name), type(e).__name__, e,
                        ))

                log("[IFLOAD] OK    nic={0} dur={1:.2f}s nat_loaded={2}".format(
                    to_s(if_name), time.time() - t0, nic.nat is not None,
                ))
                return nic
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                log("[IFLOAD] CANC  nic={0} dur={1:.2f}s".format(
                    to_s(if_name), time.time() - t0,
                ))
                raise
            except asyncio.TimeoutError:
                log("[IFLOAD] FAIL  nic={0} dur={1:.2f}s reason=phase_timeout(start_cap={2}s)".format(
                    to_s(if_name), time.time() - t0, start_cap,
                ))
                return None
            except (OSError, InterfaceNotFound, InterfaceInvalidAF) as e:
                log("[IFLOAD] FAIL  nic={0} dur={1:.2f}s reason={2}: {3}".format(
                    to_s(if_name), time.time() - t0, type(e).__name__, repr(e),
                ))
                log_exception()
                return None
            except Exception as e:  # pylint: disable=broad-except
                log("[IFLOAD] FAIL  nic={0} dur={1:.2f}s reason={2}: {3}".format(
                    to_s(if_name), time.time() - t0, type(e).__name__, repr(e),
                ))
                log_exception()
                return None

    sweep_t0 = time.time()
    log("[IFLOAD-SWEEP] start n_names={0} concurrency={1}".format(
        len(if_names), LOAD_CONCURRENCY,
    ))
    results = await asyncio.gather(*[load_one(n) for n in if_names])
    loaded = [nic for nic in results if nic is not None]

    # MAC-based dedup: defence in depth.  The Windows netifaces shim's
    # .interfaces() historically yielded both the friendly name and
    # the adapter description for one physical NIC (fixed at source);
    # users can also pass --nic <name> --nic <description> by hand
    # and hit the same alias.  Either way we end up running the full
    # nic.start + load_nat pipeline twice on what the kernel sees as
    # one interface, wasting 4-10 s of startup and producing two
    # Interface objects whose downstream NAT predictions are
    # identical.  Drop duplicates by MAC, keeping the first instance.
    # MACs are populated by nic.start; NICs that failed to start are
    # already filtered out above.  Defensive: a missing MAC (None /
    # "") never dedups, so VLAN sub-interfaces and bridges keep their
    # individual entries.
    mac_to_kept_name = {}
    deduped = []
    for nic in loaded:
        mac = getattr(nic, "mac", None)
        nic_name = to_s(getattr(nic, "name", "?"))
        if mac and mac in mac_to_kept_name:
            kept = mac_to_kept_name[mac]
            # Loud warn -- caller likely passed two --nic flags for the
            # same physical NIC, or the netifaces backend leaked an
            # alias.  Either way the user should know we collapsed
            # them; silently dropping was the bug that hid the
            # Windows enumeration regression for months.
            msg = (
                "[IFLOAD-SWEEP] DUPLICATE NIC: name={0!r} maps to the "
                "same MAC ({1}) as already-loaded name={2!r}; "
                "dropping the duplicate.  This is usually one of: "
                "(a) --nic passed twice with friendly name + "
                "description for one Windows adapter; "
                "(b) two host-only / NAT virtual adapters sharing a "
                "MAC; (c) a netifaces shim emitting aliases.  Check "
                "your --nic args / Network Connections panel."
            ).format(nic_name, mac, kept)
            log(msg)
            continue
        if mac:
            mac_to_kept_name[mac] = nic_name
        deduped.append(nic)

    log("[IFLOAD-SWEEP] done dur={0:.2f}s loaded={1}/{2} unique={3}".format(
        time.time() - sweep_t0, len(loaded), len(if_names), len(deduped),
    ))
    return deduped


def get_nic_for_af(nic_list):
    """Return a {IP4: nic, IP6: nic} dict mapping each address family to the first NIC that supports it."""
    ret = {IP4: None, IP6: None}
    for af in (IP4, IP6):
        for nic in nic_list:
            if af in nic.supported():
                ret[af] = nic
                break

    return ret
