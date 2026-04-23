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
) -> List[Tuple[int, str]]:
    """Resolve a hostname via the OS getaddrinfo call, returning (af, ip) pairs for known families."""
    loop = get_running_loop()

    # Uses a process pool executor.
    # Caution needed here.
    addr_infos = await loop.getaddrinfo(
        host,
        None,
    )

    # Pull out IP4 and IP6 results.
    results = []
    for addr_info in addr_infos:
        for af in VALID_AFS:
            if af == addr_info[0]:
                ip = ip_norm(addr_info[4][0])
                result = (af, ip)
                results.append(result)

    return results


class DestTup:
    """Resolved destination tuple holding address family, IP, port, and IP-range metadata."""

    def __init__(self, af: int, ip: str, port: int, ipr: Any) -> None:
        if ipr is None:
            raise KeyError("AF not found for address")

        self.af = af
        self.ip = ip
        self.port = port
        self.ipr = ipr
        # IPv6 link-local addresses with a scope (%ens34, %2) need a 4-tuple
        # (host, port, flowinfo, scope_id) for sock_connect to work.
        # getaddrinfo resolves the scope notation synchronously for IP literals.
        if af == IP6 and "%" in ip:
            try:
                infos = _socket.getaddrinfo(ip, port, _socket.AF_INET6, _socket.SOCK_STREAM)
                self.tup = infos[0][4]
            except OSError:
                self.tup = (ip, port)
        else:
            self.tup = (ip, port)
        self.is_private = ipr.is_private
        self.is_public = ipr.is_public
        self.is_loopback = ipr.is_loopback
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
        self.resolved = False

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
        except asyncio.CancelledError:  # pylint: disable=try-except-raise
            raise
        except (ValueError, OSError):
            # Resolve domain to IP.
            try:
                # Uses a manual DNS req to resolve a domain.
                # Bypasses any DNS errors.
                results = await asyncio.wait_for(
                    async_res_domain(host, route), self.conf["dns_timeout"]
                )

                # Ensure some IPs returned.
                if not len(results):
                    raise ValueError("Using fallback DNS")
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                raise
            except (OSError, asyncio.TimeoutError, ValueError, ImportError):
                # If that fails -- fallback to getaddrinfo.
                results = await asyncio.wait_for(
                    sock_res_domain(host, route), self.conf["dns_timeout"]
                )

                # Otherwise complete failure.
                if not len(results):
                    raise LookupError("could not resolve addr.")

            # Save results in class field.
            for result in results:
                _, ip = result
                await self.res(route=route, host=ip)

        self.resolved = True
        return self

    def __await__(self) -> Any:
        return self.res().__await__()

    def select_ip(self, af: int) -> "DestTup":
        """Return a DestTup for the resolved IP matching the given address family."""
        if af == IP4:
            ip, ipr = self.IP4, self.v4_ipr
        if af == IP6:
            ip, ipr = self.IP6, self.v6_ipr

        return DestTup(af, ip, self.port, ipr)


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
