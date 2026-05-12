"""IP address range (prefix) parsing and arithmetic."""

import ipaddress
import copy
from functools import total_ordering
from ..utility.utils import fstr, log, range_intersects, hamming_weight, get_bits
from .net_defs import BLACK_HOLE_IPS, IP4, IP6, IPA_TYPES, IP_PRIVATE, IP_PUBLIC
from .net_utils import af_bitlen, cidr_to_netmask, ip_norm, v_to_af

__all__ = [
    "IPRangeIter",
    "IPRange",
    "ipr_in_interfaces",
    "ipr_norm",
    "IPR",
    "ensure_ip_is_public",
]


class IPRangeIter:
    """Iterator over the host addresses within an IPRange, supporting forward and reverse traversal."""

    def __init__(self, ipr, reverse=False):
        self.ipr = ipr
        self.reverse = reverse
        self.host_p = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.host_p >= self.ipr.host_no:
            raise StopIteration

        if not self.reverse:
            ipa_ip = self.ipr[self.host_p]
        else:
            ipa_ip = self.ipr[(len(self.ipr) - 1) - self.host_p]

        self.host_p += 1
        return ipa_ip


"""
Represents a block of distinct IP assignments.
bitlen is the number of host bits in the block — the counterpart to netmask.
Both describe the same thing: bitlen=8 and netmask="255.255.255.0" both mean
a /24 block with 255 usable hosts. A single host has bitlen=0 (no host bits).
subnet separately stores the OS-assigned network prefix when known (e.g.
subnet=64 for an address inside a /64, even when bitlen=0 for a single host).

Accepts str, int, bytes for IP and netmask.
Can be converted to str, int, or bytes.
Iterable and sliceable -- returns ip_addr objs.
"""


@total_ordering
class IPRange:
    """Represents a block of IP addresses described by a base address and a host-bit length."""

    def __init__(
        self,
        ip,
        netmask=None,
        bitlen=None,
        af=None,
    ):
        self.route = None
        self.subnet = None

        # When AF is forced but no bitlen given, default to single host.
        if af and bitlen is None:
            bitlen = 0

        # Netmask takes precedence; suppress bitlen so only one path runs.
        if netmask is not None:
            bitlen = None

        # Default: single host (no host bits).
        if bitlen is None and netmask is None:
            bitlen = 0

        if netmask is None and bitlen is None:
            raise ValueError("Either netmask or bitlen must be provided")
        if ip == netmask:
            raise ValueError("ip and netmask must not be equal")

        # Normalise netmask: remove /n, %iface, and/or explode compressed IPv6.
        if isinstance(netmask, str):
            self.netmask = ip_norm(netmask)
        elif netmask is None:
            self.netmask = None
        else:
            self.netmask = netmask
            if netmask in (32, 128):
                log(
                    "Netmask value looks like a bit-length — did you mean bitlen= instead?"
                )

        # Determine address family (IPv4 vs IPv6) and check for ambiguity.
        self.af = None
        if isinstance(ip, int):
            if ip < (2**31):
                if netmask is None:
                    raise ValueError(
                        "Cannot determine address family: integer IP is ambiguous without a netmask."
                    )
                ipa_netmask = ipaddress.ip_address(netmask)
                self.af = v_to_af(ipa_netmask.version)

        # Norm IP -- remove /n, %iface, and/or explode.
        if isinstance(ip, str):
            self.ip = ip_norm(ip)
        else:
            self.ip = ip

        # Use specific AF.
        if self.af is not None:
            if self.af == IP4:
                self.ipa_ip = ipaddress.IPv4Address(self.ip)
            if self.af == IP6:
                self.ipa_ip = ipaddress.IPv6Address(self.ip)
        else:
            self.ipa_ip = ipaddress.ip_address(self.ip)
            self.af = v_to_af(self.ipa_ip.version)

        # Derive netmask from bitlen (host bit count), or bitlen from netmask.
        max_bits = af_bitlen(self.af)
        if bitlen is not None:
            self.netmask = cidr_to_netmask(max_bits - bitlen, self.af)
            self.bitlen = bitlen
        else:
            ipa_netmask = ipaddress.ip_address(self.netmask)
            self.bitlen = max_bits - hamming_weight(int(ipa_netmask))

        if self.bitlen > max_bits:
            raise ValueError("bitlen {} exceeds max {} for AF".format(self.bitlen, max_bits))
        host_bit_len = self.bitlen

        # IP is network portion + host portion.
        self.i_ip = int(self.ipa_ip)

        # Blank out the host segment of i_ip so that offset calculations
        # work against the network portion only.  i_host holds the original
        # host portion (max value the host bits can represent), and i_ip
        # ends up containing only the network portion.
        if host_bit_len:
            self.i_host = get_bits(self.i_ip, length=host_bit_len)
            self.i_ip -= self.i_host
            self.host_no = 1
        else:
            # bitlen=0: no host bits — this is a single host address.
            self.i_host = 0
            self.host_no = 1
            self.i_nw = self.i_ip

        # Blank host portion means this is a range of IPs.
        # That is - it is a network.
        if host_bit_len:
            self.i_nw = self.i_ip
            if host_bit_len != max_bits:
                self.host_no = (2**host_bit_len) - 1

        # IP may have a blank host portion but the set bits
        # still seem to provide enough info for this to work.
        self.is_private = self.ipa_ip.is_private
        self.is_public = not self.is_private
        if not self.i_ip:
            self.is_public = True
            self.is_private = False

        if self.ip in BLACK_HOLE_IPS.values():
            self.is_public = True
            self.is_private = False

        # Used for range comparisons.
        if self.bitlen == 0:
            self.r = [self.i_nw, self.i_nw]
        else:
            self.r = [self.i_nw, self.i_nw + self.host_no]

        if not self.host_no:
            raise ValueError("host_no must be non-zero")

    @property
    def host_limit(self):
        return self.host_no

    def len(self):
        """Return the number of host addresses in this range."""
        return self.host_no

    def ip_f(self, n):
        """Return an IPv4Address or IPv6Address object for the integer address n."""
        if self.af == IP4:
            return ipaddress.IPv4Address(n)
        if self.af == IP6:
            return ipaddress.IPv6Address(n)

    def to_dict(self):
        """Serialise this IPRange to a plain dict suitable for JSON or pickling."""
        d = {"ip": self.ip, "host_limit": self.host_no, "af": int(self.af)}
        if self.subnet is not None:
            d["subnet"] = self.subnet
        return d

    @staticmethod
    def from_dict(d):
        """Reconstruct an IPRange from a dict previously produced by to_dict."""
        import math

        host_limit = d["host_limit"]
        bitlen = 0 if host_limit <= 1 else math.ceil(math.log2(host_limit + 1))
        ipr = IPRange(ip=d["ip"], bitlen=bitlen)
        if "subnet" in d:
            ipr.subnet = d["subnet"]
        return ipr

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    def __deepcopy__(self, memo):
        ip = self.ip
        netmask = self.netmask
        params = (ip, netmask, copy.deepcopy(self.bitlen))
        new_ipr = IPRange(*params)
        new_ipr.subnet = self.subnet
        return new_ipr

    def __int__(self):
        return self.i_nw + self.i_host

    def __bytes__(self):
        if self.af == IP4:
            return int.to_bytes(
                int(self),
                4,
                "big",
            )
        if self.af == IP6:
            return int.to_bytes(
                int(self),
                16,
                "big",
            )

    def __len__(self):
        return self.host_no

    def __iter__(self):
        return IPRangeIter(self)

    def __reversed__(self):
        return IPRangeIter(self, reverse=True)

    def get_value(self, i):
        """
        Return the IP address at offset i within this subnet.

        Modulus arithmetic is used so that:
        - Negative indexes wrap backwards through the host range.
        - Indexes beyond host_no wrap around (subnet is treated as circular).
        - Host addresses start at 1, not 0, so the offset is shifted by +1
          for non-negative indexes (the or-1 guard handles the edge case where
          the subnet has a blank host portion that would otherwise yield 0).
        """
        # bitlen=0 means single host — index always returns the address itself.
        if self.bitlen == 0:
            return self.ip_f(self.i_nw)

        # Negative index: use as-is to wrap backwards.
        # Non-negative index: shift by +1 so hosts start counting from 1.
        offset = i if i < 0 else i + 1

        i_host = (offset % (self.host_no + 1)) or 1
        return self.ip_f(self.i_nw + i_host)

    def __add__(self, n):
        if isinstance(n, IPRange):
            return self[n.i_host]

        if isinstance(n, int):
            return self[n]

        raise NotImplementedError("IPRange.__add__ is not implemented for that type.")

    def __radd__(self, n):
        return self + n

    def __sub__(self, n):
        if isinstance(n, IPRange):
            return self[-n.i_host]

        if isinstance(n, int):
            return self[-n]

        raise NotImplementedError("IPRange.__sub__ is not implemented for that type.")

    def __rsub__(self, n):
        return self - n

    def convert_other(self, other):
        """Coerce other to an IPRange for comparison operations."""
        if isinstance(other, (int, bytes, str)):
            ipa = ipaddress.ip_address(other)
            return IPRange(ipa)
        if isinstance(other, IPRange):
            return other
        if isinstance(other, IPA_TYPES):
            return IPRange(other)
        raise NotImplementedError(
            "IPRange comparison is not implemented for that type."
        )

    def __eq__(self, other):
        other = self.convert_other(other)
        return range_intersects(self.r, other.r)

    def __lt__(self, other):
        other = self.convert_other(other)

        # Compare highest values in range.
        return self.r[1] < other.r[1]

    def __contains__(self, item):
        return self == item

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            return [self[i] for i in range(start, stop, step)]
        if isinstance(key, int):
            return self.get_value(key)
        if isinstance(key, tuple):
            return [self.get_value(x) for x in key]
        raise TypeError("Invalid argument type: {}".format(type(key)))

    def __repr__(self):
        return fstr("{0}", (str(self),))

    # Get an IPAddress obj at start of range.
    # Convert to a string.
    def __str__(self):
        return ipr_norm(self)

    def __hash__(self):
        return hash(str(self))


def ipr_in_interfaces(
    needle_ipr, if_list, mode=IP_PUBLIC
):
    """Return True if needle_ipr matches any public (or private) IP in the given interface list."""
    af = needle_ipr.af
    for interface in if_list:
        routes = interface.rp[af].routes
        for route in routes:
            if mode == IP_PUBLIC:
                search_list = route.ext_ips
            if mode == IP_PRIVATE:
                search_list = route.nic_ips

            for hey_ipr in search_list:
                if needle_ipr in hey_ipr:
                    return True

    return False


def ipr_norm(ipr):
    """Return the normalised string of the first (or only) host address in an IPRange."""
    return ip_norm(str(ipr[0]))


def IPR(ip, af=None, bitlen=0):
    """Construct a single-host IPRange, inferring address family from the IP string when af is None."""
    af = af or IP6 if ":" in ip else IP4
    return IPRange(ip, af=af, bitlen=bitlen)


def ensure_ip_is_public(ip):
    """Normalise ip and raise if it is a private address; return the normalised IP on success."""
    ip = ip_norm(ip)
    ipr = IPRange(ip)
    if ipr.is_private:
        raise ValueError("IP must be public.")

    return ip


if __name__ == "__main__":  # pragma: no cover
    # Blank host = range.
    x = IPRange("192.168.1.0", "255.255.255.0")

    assert str(x[0]) == "192.168.1.1"
    assert str(x[1]) == "192.168.1.2"
    assert str(x[-1]) == "192.168.1.255"
    assert str(x[-2]) == "192.168.1.254"
    assert x.host_no == 255

    # Not blank host = single host. Not a range.
    y = IPRange("192.168.1.179", "255.255.255.0")
    assert str(y[0]) == "192.168.1.179"
    assert str(y[1]) == "192.168.1.179"
    assert str(y[-1]) == "192.168.1.179"
    assert str(y[-2]) == "192.168.1.179"
    assert y.host_no == 1

    # Single host (with full net mask). Also not a range.
    z = IPRange("7.7.7.7", "255.255.255.255")
    assert str(z[0]) == "7.7.7.7"
    assert str(z[15]) == "7.7.7.7"
    assert str(z[-15]) == "7.7.7.7"
    assert z.host_no == 1

    a = IPRange("7.7.7.7", "255.255.255.255")
    b = IPRange("7.7.7.7", "255.255.255.255")
    c = IPRange("7.7.7.8", "255.255.255.255")
    d = IPRange("192.168.1.1", "255.255.255.0")
    e = IPRange("192.168.1.0", "255.255.255.0")
    f = IPRange("192.169.0.0", "255.255.0.0")
    g = IPRange("192.168.2.1", "255.255.255.0")
    h = IPRange("192.168.1.20", "255.255.255.0")
    assert a == b  # Same IP
    assert b < c  # CMP single ip values
    assert a != c  # Not same IP
    assert d == e  # Check if IP in a range.
    assert f != e  # Compare two ranges for intersection.
    assert b < e  # Compare end value of ranges.
    assert e > b

    assert f > e  # Range compare is based on host no, not ip value

    points = [a, c, e]
    assert d in points
    assert b in points
    assert g not in points
    assert h in points
    x = IPRange("fe80::9acb:c90e:7bf6:a093%enp3s0", "ffff:ffff:ffff:ffff::/64")
    assert x.bitlen == 64  # 64 host bits in a /64

