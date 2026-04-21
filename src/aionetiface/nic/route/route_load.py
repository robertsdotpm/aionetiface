import asyncio
import copy
import random
from ...net.ip_range import *
from ..netifaces.netiface_extra import *
from ...net.address import *
from .route_pool import *
from ...utility.pattern_factory import *
from ...settings import *
from .route_utils import *
from ...net.bind.bind import *

"""
Loads external IP associated with a nic IP.
Give a single address for a NIC (may appear public or private) --
use STUN to lookup what WAN address ends up being reported after using
that particular address for a bind() call.
"""
async def lookup_wan_ip_for_nic_ip(src_ip, min_agree, stun_clients, timeout):
    if not stun_clients:
        log("lookup_wan_ip_for_nic_ip: no STUN clients available, cannot resolve WAN IP.")
        return None

    interface = stun_clients[0].interface
    af = stun_clients[0].af
    # send_recv_loop already retries 3x internally per server; one outer
    # retry covers genuine transient packet loss without tripling latency
    # when STUN servers are systemically unreachable.
    for attempt in range(2):
        try:
            tasks = []
            for stun_client in stun_clients:
                try:
                    local_addr = await asyncio.wait_for(
                        Bind(
                            stun_client.interface,
                            af=stun_client.af,
                            port=0,
                            ips=src_ip
                        ).res(),
                        timeout=2.0
                    )
                except asyncio.TimeoutError:
                    log(fstr("Bind timed out for {0}, skipping client.", (src_ip,)))
                    continue
                if local_addr is None:
                    continue

                task = async_wrap_errors(
                    stun_client.get_wan_ip(pipe=local_addr),
                    logging=False
                )
                tasks.append(task)

            if not tasks:
                return None

            wan_ip = await concurrent_first_agree_or_best(
                min_agree,
                tasks,
                timeout,
                wait_all=False
            )

            if wan_ip is not None:
                host_limit = af_bitlen(af)
                ext_ipr = IPRange(wan_ip, host_limit=host_limit)
                nic_ipr = IPRange(src_ip, host_limit=host_limit)
                if nic_ipr.is_private or src_ip != wan_ip:
                    nic_ipr.is_private = True
                    nic_ipr.is_public = False
                else:
                    nic_ipr.is_private = False
                    nic_ipr.is_public = True
                return (src_ip, Route(af, [nic_ipr], [ext_ipr], interface))

        except Exception:
            log_exception()

        if attempt == 0:
            log(fstr("WAN IP lookup for {0} failed, retrying.", (src_ip,)))
            await asyncio.sleep(0.5)

    return None

STUN_BATCH_SIZE = 4

async def run_stun_tasks_batched(tasks):
    """
    Run STUN tasks in small batches with jitter between batches to avoid
    flooding the router with a UDP burst.
    """
    results = []
    for i in range(0, len(tasks), STUN_BATCH_SIZE):
        batch = tasks[i:i + STUN_BATCH_SIZE]
        batch_results = await asyncio.gather(*batch)
        results.extend(batch_results)
        if i + STUN_BATCH_SIZE < len(tasks):
            await asyncio.sleep(random.uniform(0.05, 0.3))
    return results


def group_pub_iprs_by_subnet(pub_iprs, max_bits):
    """
    Group public IPRange objects by their OS network prefix (subnet).
    Returns (group_heads, individual_iprs):
      - group_heads: {head_src_ip: [rest_iprs]} for IPs sharing a subnet
      - individual_iprs: list of IPRanges that must be queried individually
                         (IPv6 /128, or any IP whose subnet is unknown)
    """
    net_groups = {}
    individual_iprs = []

    for ipr in pub_iprs:
        nc = getattr(ipr, 'subnet', None)
        if nc is None:
            nc = max_bits

        # IPv6 /128 (or any max-prefix IP) always gets its own STUN query.
        if nc == max_bits:
            individual_iprs.append(ipr)
            continue

        ip_int = int(ipr)
        host_bits = max_bits - nc
        network_int = (ip_int >> host_bits) << host_bits
        key = (network_int, nc)
        if key not in net_groups:
            net_groups[key] = []
        net_groups[key].append(ipr)

    group_heads = {}
    for group in net_groups.values():
        head_ipr = group[0]
        src_ip = ip_norm(str(head_ipr[0]))
        group_heads[src_ip] = group[1:]

    return group_heads, individual_iprs

"""
Network interface cards have a list of addresses to bind on them.
They consist of one or more ranges of IPs. A range may have one IP in it.
Depending on the gateway and route tables -- binding to any of those IPs
ends up with a certain public address from another machines perspective on
the Internet. To discover that perspective -- STUN is used.

However, since public STUN servers are used a portion of them may be adversarial
(or simply misconfigured to return bad results.) So this function allows for
public addresses to be discovered assuming that a minimum number of STUN
servers report the same result. It is optimized so that if there are ranges
of IPs for a NIC (with a million IPs for example) -- it only checks the
first address to learn an associated IP and then generalized the result.

Servers often like to directly set public addresses for their NIC cards
to indicate that they're directly connected to the Internet without NATs
or any of that junk. In that case -- the software still checks if these are
valid addresses because a machine is free to set whatever addresses they like
for their interface but it doesn't mean that the addresses are valid.
"""
async def discover_nic_wan_ips(af, min_agree, enable_default, interface, stun_clients, netifaces, timeout):
    # Get a list of tasks to resolve NIC addresses.
    tasks = []
    link_locals = []
    priv_iprs = []
    nic_iprs = await get_nic_iprs(af, interface, netifaces)
    pub_iprs = []
    for nic_ipr in nic_iprs:
        assert(int(nic_ipr[0]))
        if ip_norm(nic_ipr[0])[:2] in ["fe", "fd"]:
            link_locals.append(nic_ipr)
            log(fstr("Addr is link local so skipping"))
            continue

        if nic_ipr.is_private:
            priv_iprs.append(nic_ipr)
        else:
            pub_iprs.append(nic_ipr)

    # Determine the OS-preferred source address before grouping so we can
    # promote it to group head (it's the most reliable address for STUN).
    host_limit = af_bitlen(af)
    af_default_nic_ip = ""
    if enable_default:
        dest = "8.8.8.8" if af == IP4 else "2001:4860:4860::8888"
        af_default_nic_ip = ip_norm(determine_if_path(af, dest))

    # If af_default_nic_ip is in pub_iprs, move it to the front so that
    # group_pub_iprs_by_subnet picks it as the head of its subnet group.
    # Deprecated temporary addresses are unreliable for STUN; using the
    # OS-preferred address avoids silent STUN failures for the whole group.
    if af_default_nic_ip:
        for i, ipr in enumerate(pub_iprs):
            if ip_norm(str(ipr[0])) == af_default_nic_ip:
                pub_iprs = [ipr] + pub_iprs[:i] + pub_iprs[i+1:]
                break

    # Group public IPs by OS network prefix (subnet).
    # One STUN query per subnet group; individual IPs (IPv6 /128 or unknown
    # prefix) each get their own query. Rest of a group derive their route
    # from the head's result after resolution.
    max_bits = 128 if af == IP6 else 32
    pub_group_heads, individual_iprs = group_pub_iprs_by_subnet(pub_iprs, max_bits)

    for src_ip in pub_group_heads:
        tasks.append(
            async_wrap_errors(
                lookup_wan_ip_for_nic_ip(
                    src_ip,
                    min_agree,
                    stun_clients,
                    timeout
                )
            )
        )

    for ipr in individual_iprs:
        src_ip = ip_norm(str(ipr[0]))
        pub_group_heads[src_ip] = []
        tasks.append(
            async_wrap_errors(
                lookup_wan_ip_for_nic_ip(
                    src_ip,
                    min_agree,
                    stun_clients,
                    timeout
                )
            )
        )

    # Add a default-route task only when af_default_nic_ip is not already
    # being queried as a pub group head (avoids a duplicate STUN request).
    af_default_is_pub_head = af_default_nic_ip in pub_group_heads
    if enable_default and not af_default_is_pub_head:
        tasks.append(
            async_wrap_errors(
                lookup_wan_ip_for_nic_ip(
                    af_default_nic_ip,
                    min_agree,
                    stun_clients,
                    timeout
                )
            )
        )

    # Append task to get route using priv nic.
    """
    Optimization:
    If there was only one private NIC IPR and enable default already ran.
    It's already done the necessary work to resolve that first route.
    So only run the code bellow if there's more than 1 or enable default
    has been disabled.

    > 1 or (len(priv_iprs) and not enable_default)
    """
    priv_src = ""
    if len(priv_iprs) > 1 or (len(priv_iprs) and not enable_default):
        priv_src = ip_norm(str(priv_iprs[0]))
        tasks.append(
            async_wrap_errors(
                lookup_wan_ip_for_nic_ip(
                    priv_src,
                    min_agree,
                    stun_clients,
                    timeout
                )
            )
        )

    # Resolve interface addresses in batches with jitter to avoid UDP bursts.
    results = await run_stun_tasks_batched(tasks)
    results = [r for r in results if r is not None]

    # Derive routes for non-head IPs in each network group from the head's result.
    for head_src, rest_iprs in pub_group_heads.items():
        if not rest_iprs:
            continue
        head_route = get_route_by_src(head_src, results)
        if head_route is not None:
            # For direct routing (no NAT) the head's ext_ip equals its nic_ip.
            # Each address in the group is its own distinct external IP, so
            # assign each derived route its own ext_ip rather than copying the head's.
            head_is_direct = (int(head_route.nic_ips[0]) == int(head_route.ext_ips[0]))
            for extra_ipr in rest_iprs:
                if head_is_direct:
                    ext_ipr = IPRange(ip_norm(str(extra_ipr[0])), host_limit=af_bitlen(af))
                    ext_iprs = [ext_ipr]
                else:
                    ext_iprs = copy.deepcopy(head_route.ext_ips)
                extra_route = Route(af, [extra_ipr], ext_iprs, interface)
                results.append((ip_norm(str(extra_ipr[0])), extra_route))

    # Only the default NIC will have
    # a default route enabled for the af.
    if enable_default:
        default_route = get_route_by_src(
            af_default_nic_ip,
            results
        )

        """
        If the main NIC IP for the default interface for AF
        is not in the NIC IPs for this interface then
        don't enable the use of the default route.
        """
        af_default_nic_ipr = IPRange(af_default_nic_ip, host_limit=host_limit)
        if af_default_nic_ipr not in nic_iprs:
            default_route = None
            log(fstr("Route error {0} disabling default route.", (af,)))
    else:
        default_route = None

    # Load route used for priv nics.
    priv_route = get_route_by_src(priv_src, results)

    # Exclude priv_route and default.
    # When af_default_nic_ip is a pub group head its route is already a primary
    # route (not just a fallback), so leave it in the results.
    exclude = [priv_src]
    if not af_default_is_pub_head:
        exclude.append(af_default_nic_ip)
    routes = exclude_routes_by_src(exclude, results)

    # Add a single route for all private IPs (if exists)
    # Use default routes external address (if exists)
    if len(priv_iprs):
        priv_ext = None
        if default_route is not None:
            priv_ext = default_route.ext_ips
        else:
            if priv_route is not None:
                priv_ext = priv_route.ext_ips

        if priv_ext is not None:
            priv_route = Route(af, priv_iprs, priv_ext, interface)
            routes.append(priv_route)

    # Only use default route if no other option.
    if not len(routes):
        if default_route is None:
            routes = []
        else:
            routes = [default_route]
    else:
        # Deterministic order = consistent for servers.
        routes = sort_routes(routes)

    # For IPv4: when no routes were resolved despite having private IPs (e.g.
    # no internet access so STUN failed), preserve the private IPs in
    # link_locals so topology.py can use them as a local-address fallback.
    if af == IP4 and not routes and priv_iprs:
        link_locals = priv_iprs

    # Set link locals in route list.
    [r.set_link_locals(link_locals) for r in routes]

    # Return results back to caller.
    return [af, routes, link_locals]

