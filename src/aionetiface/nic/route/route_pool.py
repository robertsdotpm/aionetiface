"""RoutePool: a set of routes grouped by address family."""
import copy
from typing import Any, Dict, List, Optional
from ...utility.utils import sorted_search
from ...net.ip_range import IPRange
from .route import Route


# Allows referencing a list of routes as if all WAN IPs
# were at their own index regardless of if they're in ranges.
# Will be very slow if there's a lot of hosts.
class RoutePoolIter:
    """Iterator that traverses a RoutePool host-by-host, optionally in reverse order."""

    def __init__(self, rp: "RoutePool", reverse: bool = False) -> None:
        self.rp = rp
        self.reverse = reverse
        self.host_p = 0
        self.route_offset = 0

        # Point to the end route -- we're counting backwards.
        if self.reverse:
            self.route_offset = len(self.rp.routes) - 1

    def __iter__(self) -> "RoutePoolIter":
        return self

    def __next__(self) -> Any:
        # Avoid overflow.
        if self.host_p >= self.rp.wan_hosts:
            raise StopIteration

        # Offset used for absolute position of WAN host.
        if not self.reverse:
            host_offset = self.host_p
        else:
            host_offset = (len(self.rp) - 1) - self.host_p

        # Get a route object encapsulating that WAN host.
        route = self.rp.get_route_info(self.route_offset, host_offset)

        # Adjust position of pointers.
        self.host_p += 1
        if not self.reverse:
            if self.host_p >= self.rp.len_list[self.route_offset]:
                if self.route_offset < len(self.rp.routes) - 1:
                    self.route_offset += 1
        else:
            if self.host_p >= self.rp.len_list[self.route_offset]:
                if self.route_offset:
                    self.route_offset -= 1

        # Return the result.
        return route


class RoutePool:
    """Ordered collection of Route objects that supports indexing across WAN host addresses."""

    def __init__(
        self,
        routes: Optional[List[Any]] = None,
        link_locals: Optional[List[Any]] = None,
    ) -> None:
        self.routes = routes or []
        self.link_locals = link_locals or []

        # Avoid duplicates in routes.
        seen = []
        for route in self.routes:
            if route not in seen:
                seen.append(route)
        self.routes = seen

        # Make a list of the address size for WAN portions of routes.
        # Such information will be used for dereferencing routes.
        self.len_list = []
        self.wan_hosts = 0
        for i in range(0, len(self.routes)):
            # Link route to route pool.
            self.routes[i].link_route_pool(self)
            self.routes[i].set_offsets(route_offset=i)

            # No WAN ipr section defined.
            if not len(self.routes[i].ext_ips):
                self.len_list.append(self.wan_hosts)
                continue

            # Append val to len_list = current hosts + wan hosts at route.
            next_val = self.wan_hosts + len(self.routes[i].ext_ips[0])
            self.len_list.append(next_val)
            self.wan_hosts = next_val

        # Index into the routes list.
        self.route_index = 0

        # Simulate 'removing' past elements.
        self.pop_pointer = 0

    def to_dict(self) -> List[Dict[str, Any]]:
        """Serialise this pool to a list of route dicts suitable for JSON storage."""
        routes = []
        for route in self.routes:
            routes.append(route.to_dict())

        return routes

    @staticmethod
    def from_dict(route_dicts: List[Dict[str, Any]]) -> "RoutePool":
        """Reconstruct a RoutePool from a list of route dicts previously produced by to_dict."""
        routes = []
        for route_dict in route_dicts:
            routes.append(Route.from_dict(route_dict))

        return RoutePool(routes)

    # Pickle.
    def __getstate__(self) -> List[Dict[str, Any]]:
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state: List[Dict[str, Any]]) -> None:
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    def locate(self, other: Any) -> Optional[Any]:
        """Return the first route in the pool equal to other, or None if not found."""
        for route in self.routes:
            if route == other:
                return route

        return None

    # Is a route in this route pool?
    def __contains__(self, other: Any) -> bool:
        route = self.locate(other)
        if route is not None:
            return True
        else:
            return False

    # Simulate fetching a route off a stack of routes.
    # Just hides certain pointer offsets when indexing, lel.
    def pop(self) -> Any:
        """Return the next route in traversal order, advancing the internal pop pointer."""
        if self.pop_pointer >= self.wan_hosts:
            raise Exception("No more routes.")

        ret = self[self.pop_pointer]
        self.pop_pointer += 1

        return ret

    def get_route_info(self, route_offset: int, abs_host_offset: int) -> Any:
        """Build and return a single-host Route for the WAN host at abs_host_offset within route_offset."""
        # Route to use for the WAN addresses.
        assert route_offset <= (len(self.routes) - 1)
        route = self.routes[route_offset]

        # Convert host_offset to a index inside route's WAN subnet.
        prev_len = self.len_list[route_offset - 1] if route_offset else 0
        rel_host_offset = abs_host_offset - prev_len
        assert rel_host_offset <= self.len_list[route_offset] - 1

        # Get references to member objs.
        wan_ipr = route.ext_ips[0]
        nic_ipr = route.nic_ips[0]

        # For pub ranges assigned to NIC -- they will line up.
        # For N or more private addressess -> a WAN = probably won't.
        # In such a case it doesn't matter as any NIC IP = the same WAN.
        assert rel_host_offset + 1 <= self.wan_hosts
        assert len(wan_ipr)
        assert len(nic_ipr)
        rel_host_offset = rel_host_offset % self.wan_hosts

        # Build a route corrosponding to these offsets.
        wan_ip = IPRange(str(wan_ipr[rel_host_offset]), bitlen=0)
        new_route = Route(
            af=route.af,
            nic_ips=copy.deepcopy(route.nic_ips),
            ext_ips=[wan_ip],
            interface=route.interface,
        )
        new_route.set_link_locals(copy.deepcopy(route.link_locals))
        new_route.set_offsets(route_offset, abs_host_offset)
        new_route.link_route_pool(self)

        return new_route

    def __len__(self) -> int:
        return self.wan_hosts

    def __getitem__(self, key: Any) -> Any:
        # Possible due to pop decreasing host no.
        if not self.wan_hosts:
            return []

        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            return [self[i] for i in range(start, stop, step)]
        elif isinstance(key, int):
            # Convert negative index to positive.
            # Sorted_search doesn't work with negative indexex.
            if key < 0:
                key = key % self.wan_hosts

            route_offset = sorted_search(self.len_list, key + 1)
            if route_offset is None:
                return None
            else:
                return self.get_route_info(route_offset, key)
        elif isinstance(key, tuple):
            return [self[x] for x in key]
        else:
            raise TypeError("Invalid argument type: {}".format(type(key)))

    def __iter__(self) -> RoutePoolIter:
        return RoutePoolIter(self)

    def __reversed__(self) -> RoutePoolIter:
        return RoutePoolIter(self, reverse=True)
