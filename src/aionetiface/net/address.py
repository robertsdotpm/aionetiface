"""Parsed network address representation."""
import asyncio
import socket as _socket
from typing import Any, List, Optional, Tuple
from ..utility.utils import strip_none, to_s, get_running_loop
from .net_defs import IP4, IP6, NET_CONF, VALID_AFS, VALID_LOOPBACKS
from .net_utils import ip_norm
from .ip_range import IPRange, ipr_norm
from .bind.bind_utils import patch_connect_ip


DNS_NAMESERVERS = {
    IP4: [
        # OpenDNS.
        "208.67.222.222",
        "208.67.220.220",
    ],
    IP6: [
        # OpenDNS.
        "2620:119:35::35",
        "2620:119:53::53",
    ],
}


async def async_res_domain_af(af: int, host: str) -> Optional[Tuple[int, str]]:
    """Resolve a hostname to a single IP address for the specified address family using aiodns."""
    # Throw error if not installed.
    # So auto fallback to getaddrinfo.
    import aiodns

    # Get IP of domain based on specific address family.
    nameservers = DNS_NAMESERVERS[af]
    resolver = aiodns.DNSResolver(nameservers=nameservers)
    if af == IP4:
        query_type = "A"
    else:
        query_type = "AAAA"

    # On success use first returned result.
    results = await resolver.query(host, query_type)
    if len(results):
        result = results[0]
        ip = ip_norm(result.host)
        return (af, ip)


async def async_res_domain(
    host: str, route: Optional[Any] = None
) -> List[Tuple[int, str]]:
    """Resolve a hostname concurrently for all valid address families, returning (af, ip) pairs."""
    # Make a list of DNS res tasks.
    tasks = []
    for af in VALID_AFS:
        tasks.append(async_res_domain_af(af, host))

    # Concurrently get IP fields from domain.
    return strip_none(await asyncio.gather(*tasks, return_exceptions=False))


async def sock_res_domain(
    host: str, route: Optional[Any] = None
) -> List[Tuple[int, Any]]:
    """Resolve a hostname via getaddrinfo; returns (af, sockaddr) pairs for known families.

    sockaddr is the kernel's address tuple from getaddrinfo result[4]
    -- (host, port) for v4, (host, port, flowinfo, scope_id) for v6.
    Preserved end-to-end so callers don't have to re-resolve scope
    info downstream.
    """
    loop = get_running_loop()

    # Uses a threading pool executor.
    # Caution needed here.
    addr_infos = await loop.getaddrinfo(
        host,
        None,
    )

    results = []
    for addr_info in addr_infos:
        for af in VALID_AFS:
            if af == addr_info[0]:
                sockaddr = list(addr_info[4])
                sockaddr[0] = ip_norm(sockaddr[0])
                results.append((af, tuple(sockaddr)))

    return results


def resolve_dest_tup(af: int, ip: str, port: int, sock_type: int = _socket.SOCK_STREAM) -> Any:
    """Return a sendto/connect tuple for af/ip/port, resolving v6 link-local scope.

    IPv6 link-local addresses with a scope suffix (fe80::...%ens34,
    ...%2) need the (host, port, flowinfo, scope_id) 4-tuple form for
    the kernel to route them deterministically -- the bare 2-tuple
    silently falls back to the OS-default NIC on multi-NIC hosts.

    The %scope notation in *ip* was already attached by
    patch_connect_ip when the Address resolver ran; we just have to
    split it back out into the 4-tuple form the kernel wants.  No
    getaddrinfo round-trip needed -- we already paid that cost
    upstream.

    sock_type is accepted for call-site symmetry with DestTup but is
    unused here (the parsed scope_id works for both TCP and UDP).
    """
    if af == IP6 and "%" in ip:
        host, scope = ip.rsplit("%", 1)
        try:
            scope_id = int(scope)
        except ValueError:
            try:
                scope_id = _socket.if_nametoindex(scope)
            except (OSError, AttributeError):
                return (ip, port)
        return (host, port, 0, scope_id)
    return (ip, port)


class DestTup:
    """Resolved destination holding af/ip/port plus the v6 flow + scope ids.

    The kernel-facing 4-tuple form for v6 link-local sendto/connect
    is built from these fields; v4 and globally-routable v6 collapse
    to the 2-tuple form. ipr metadata (is_private / is_public /
    is_loopback) was previously cached here off the IPRange that
    Address.res() built; callers that need those flags now read
    them from the IPRange directly via Address.v4_ipr / v6_ipr.
    """

    def __init__(self, af: int, ip: str, port: int, flow_id: int, scope_id: int) -> None:
        self.af = af
        self.ip = ip
        self.port = port
        self.flow_id = flow_id
        self.scope_id = scope_id
        if af == IP6 and scope_id:
            self.tup = (ip, port, flow_id, scope_id)
        else:
            self.tup = (ip, port)
        # is_loopback is consumed by socket_factory to skip the L2
        # device-pin sockopts on loopback destinations (the kernel
        # returns EINVAL when connect()ing to 127.x with
        # SO_BINDTODEVICE set). Recomputing here from the ip string
        # keeps behaviour identical to the previous ipr-derived
        # field without forcing every caller to thread an IPRange
        # through this constructor.
        self.is_loopback = ip in VALID_LOOPBACKS
        self.resolved = True

    def supported(self) -> List[int]:
        """Return a one-element list containing the address family of this destination."""
        return [self.af]


class Address:
    """Lazily-resolved network address that can hold both IPv4 and IPv6 results."""

    def __init__(
        self, host: Any, port: int, nic: Optional[Any] = None, conf: Optional[Any] = None
    ) -> None:
        self.host = host
        self.port = port
        self.nic = nic
        self.conf = conf if conf is not None else NET_CONF
        self.IP6 = self.IP4 = None
        self.v6_ipr = self.v4_ipr = None
        # v6 flow_id / scope_id captured during resolution so select_ip
        # can build a DestTup without re-resolving. For the
        # getaddrinfo path, scope comes straight from sockaddr[3];
        # for the IP-literal path, scope is derived from nic_id (the
        # interface index that patch_connect_ip just attached as %).
        # v4 has no flow/scope concept so the fields stay at 0.
        self.v6_flow_id = 0
        self.v6_scope_id = 0
        self.resolved = False
        self.dest_tup = None

    async def res(
        self, route: Optional[Any] = None, host: Optional[Any] = None
    ) -> "Address":
        """Resolve the host to IP addresses, trying aiodns first then falling back to getaddrinfo."""
        host = host or self.host
        try:
            # Ensure human-readable IPs aren't passed as binary.
            if isinstance(host, bytes):
                host = to_s(host)

            # If it can be parsed as an IP.
            # Then it's an IP.
            ipr = IPRange(host)
            ipr.is_loopback = False

            # Set route from NIC.
            if self.nic is not None:
                if route is None:
                    route = self.nic.route()

            # Used to patch IPv6 private IPs.
            if route is not None:
                nic_id = route.interface.id
            else:
                nic_id = None

            # Apply any needed IP patches.
            # ip = self.patch_ip(ipr_norm(ipr), ipr, nic_id)
            ip = patch_connect_ip(ipr.af, ipr_norm(ipr), nic_id, ipr)
            if ip in VALID_LOOPBACKS:
                ipr.is_loopback = True

            # What type of IP.
            if ipr.af == IP4:
                self.IP4 = ip
                self.v4_ipr = ipr
            if ipr.af == IP6:
                self.IP6 = ip
                self.v6_ipr = ipr
                # IP-literal path: scope comes from nic_id (the
                # interface index that patch_connect_ip just appended
                # as %). int() handles Windows' numeric ids; the
                # if_nametoindex fallback handles Unix names.
                if nic_id is not None and self.v6_scope_id == 0:
                    try:
                        self.v6_scope_id = int(nic_id)
                    except (TypeError, ValueError):
                        try:
                            self.v6_scope_id = _socket.if_nametoindex(str(nic_id))
                        except (OSError, AttributeError):
                            pass
        except asyncio.CancelledError:  # pylint: disable=try-except-raise
            raise
        except (ValueError, OSError):
            # Resolve domain to IP.
            try:
                # If that fails -- fallback to getaddrinfo.
                results = await asyncio.wait_for(
                    sock_res_domain(host, route), self.conf["dns_timeout"]
                )

                # Otherwise complete failure.
                if not len(results):
                    raise LookupError("could not resolve addr.")
            except (OSError, asyncio.TimeoutError, ValueError, ImportError):
                raise

            # Save results in class field. sock_res_domain returns
            # (af, sockaddr) where sockaddr is the kernel's tuple --
            # 2-tuple for v4, 4-tuple for v6 -- so we capture
            # flow/scope here directly without re-resolving.
            for af, sockaddr in results:
                if af == IP6 and len(sockaddr) >= 4:
                    self.v6_flow_id = sockaddr[2]
                    self.v6_scope_id = sockaddr[3]
                await self.res(route=route, host=sockaddr[0])

        self.resolved = True
        return self

    def __await__(self) -> Any:
        return self.res().__await__()

    def select_ip(self, af: int) -> "DestTup":
        """Return a DestTup for the resolved IP matching the given address family."""
        if af == IP4:
            if self.IP4 is None:
                raise KeyError("AF not found for address")
            return DestTup(af, self.IP4, self.port, 0, 0)
        if af == IP6:
            if self.IP6 is None:
                raise KeyError("AF not found for address")
            # Scope was captured in res(): from getaddrinfo's
            # sockaddr[3] for the domain path, or from nic_id for the
            # IP-literal path. No re-resolve needed here.
            return DestTup(af, self.IP6, self.port, self.v6_flow_id, self.v6_scope_id)
        raise KeyError("AF not found for address")


async def resolv_dest(af: int, dest: Any, nic: Any) -> Any:
    """Resolve a destination to a plain (ip, port) tuple, resolving domains as needed."""
    if isinstance(dest, DestTup):
        return dest.tup

    if isinstance(dest, tuple):
        try:
            # An IP -- already resolved.
            IPRange(dest[0], bitlen=0)
            return dest
        except ValueError:
            dest = await Address(*dest, nic)

    if isinstance(dest, Address):
        return dest.select_ip(af).tup
