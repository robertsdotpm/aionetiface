# TODO: Seg faults are possible with invalid CIDRs or netmasks.
# TODO: Need to write better input validation here.

import ipaddress
import copy
from functools import total_ordering
from .net_utils import *

# Sentinel CIDR value meaning "use the full address width" (i.e. a single host).
CIDR_WAN = 1000

class IPRangeIter():
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
Accepts str, int, bytes for IP and netmask.
Can be converted to str, int, or bytes.
Iterable and sliceable -- returns ip_addr objs.
"""
@total_ordering
class IPRange():
    def __init__(self, ip, netmask=None, cidr=CIDR_WAN, af=None):
        self.route = None

        # Set full bit mask based on af.
        if af:
            cidr = af_to_cidr(af)

        # Prefer netmask over cidr when both are supplied.
        if netmask is not None and cidr is not None:
            cidr = None

        # Sanity check.
        assert(netmask is not None or cidr is not None)
        assert(ip != netmask)

        # Normalise netmask: remove /n, %iface, and/or explode compressed IPv6.
        if isinstance(netmask, str):
            self.netmask = ip_norm(netmask)
        elif netmask is None:
            self.netmask = None
        else:
            self.netmask = netmask
            if netmask in (32, 128):
                log("Netmask value looks like a CIDR prefix length — did you mean cidr= instead?")

        # Determine address family (IPv4 vs IPv6) and check for ambiguity.
        self.af = None
        if isinstance(ip, int):
            if ip < (2 ** 31):
                if netmask is None:
                    raise Exception("Cannot determine address family: integer IP is ambiguous without a netmask.")
                else:
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

        # Set netmask from cidr if cidr set.
        if cidr is not None:
            if cidr:
                if cidr == CIDR_WAN:
                    cidr = max_cidr(self.af)

                self.netmask = cidr_to_netmask(cidr, self.af)

            self.cidr = cidr
        else:
            # Convert netmask to CIDR with fast binary operations.
            if netmask is not None:
                ipa_netmask = ipaddress.ip_address(self.netmask)
                self.cidr = hamming_weight(int(ipa_netmask))

        # Blank network portion.
        if not self.cidr:
            if self.af == IP4:
                self.netmask = ZERO_NETMASK_IP4
            else:
                self.netmask = ZERO_NETMASK_IP6

        # Parse IP information.
        max_host_bit_len = max_cidr(self.af)
        assert(self.cidr <= max_host_bit_len)
        host_bit_len = max_host_bit_len - self.cidr

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
            # CIDR equals the full address width — no host bits exist.
            self.i_host = 0
            self.host_no = 1
            self.i_nw = self.i_ip

        # Blank host portion means this is a range of IPs.
        # That is - it is a network.
        if host_bit_len:
            self.i_nw = self.i_ip
            if host_bit_len != max_host_bit_len:
                self.host_no = (2 ** host_bit_len) - 1

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
        if self.cidr == max_cidr(self.af):
            self.r = [self.i_nw, self.i_nw]
        else:
            self.r = [self.i_nw, self.i_nw + self.host_no]

        assert(self.host_no)

    def len(self):
        return self.host_no

    def ip_f(self, n):
        if self.af == IP4:
            return ipaddress.IPv4Address(n)
        if self.af == IP6:
            return ipaddress.IPv6Address(n)

    def to_dict(self):
        return {
            "ip": self.ip,
            "cidr": self.cidr,
            "af": int(self.af)
        }

    @staticmethod
    def from_dict(d):
        return IPRange(ip=d["ip"], cidr=d["cidr"])

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
        params = (ip, netmask, copy.deepcopy(self.cidr))
        return IPRange(*params)

    def __int__(self):
        return self.i_nw + self.i_host

    def __bytes__(self):
        if self.af == IP4:
            return int.to_bytes(
                int(self),
                4,
                'big',
            )
        if self.af == IP6:
            return int.to_bytes(
                int(self),
                16,
                'big',
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
        # A full-width CIDR means this is a single host — index always returns it.
        if self.cidr == max_cidr(self.af):
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

    def _convert_other(self, other):
        if isinstance(other, (int, bytes, str)):
            ipa = ipaddress.ip_address(other)
            return IPRange(ipa, cidr=CIDR_WAN)
        elif isinstance(other, IPRange):
            return other
        elif isinstance(other, IPA_TYPES):
            return IPRange(other, cidr=CIDR_WAN)
        else:
            raise NotImplementedError("IPRange comparison is not implemented for that type.")

    def __eq__(self, other):
        other = self._convert_other(other)
        return range_intersects(self.r, other.r)

    def __lt__(self, other):
        other = self._convert_other(other)

        # Compare highest values in range.
        return self.r[1] < other.r[1]

    def __contains__(self, item):
        return self == item

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            return [self[i] for i in range(start, stop, step)]
        elif isinstance(key, int):
            return self.get_value(key)
        elif isinstance(key, tuple):
            return [self.get_value(x) for x in key]
        else:
            raise TypeError('Invalid argument type: {}'.format(type(key)))

    def __repr__(self):
        return fstr("{0}", (str(self),))

    # Get an IPAddress obj at start of range.
    # Convert to a string.
    def __str__(self):
        return ipr_norm(self)

    def __hash__(self):
        return hash(str(self))

def ipr_in_interfaces(needle_ipr, if_list, mode=IP_PUBLIC):
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
    return ip_norm(str(ipr[0]))

def IPR(ip, af=None, cidr=CIDR_WAN):
    af = af or IP6 if ":" in ip else IP4
    return IPRange(ip, af=af, cidr=cidr)

def ensure_ip_is_public(ip):
    ip = ip_norm(ip)
    af = IP4 if "." in ip else IP6
    ipr = IPRange(ip, cidr=af_to_cidr(af))
    if ipr.is_private:
        raise Exception("IP must be public.")

    return ip

if __name__ == "__main__": # pragma: no cover
    # Blank host = range.
    x = IPRange("192.168.1.0", "255.255.255.0")

    #print(str(x[0]))
    #print(str(x[-1]))
    #exit()

    assert(str(x[0]) == "192.168.1.1")
    assert(str(x[1]) == "192.168.1.2")
    assert(str(x[-1]) == "192.168.1.255")
    assert(str(x[-2]) == "192.168.1.254")
    assert(x.host_no == 255)

    # Not blank host = single host. Not a range.
    y = IPRange("192.168.1.179", "255.255.255.0")
    assert(str(y[0]) == "192.168.1.179")
    assert(str(y[1]) == "192.168.1.179")
    assert(str(y[-1]) == "192.168.1.179")
    assert(str(y[-2]) == "192.168.1.179")
    #assert(str(x[0]) == "192.168.1.1")
    assert(y.host_no == 1)

    # Single host (with full net mask). Also not a range.
    z = IPRange("7.7.7.7", "255.255.255.255")
    assert(str(z[0]) == "7.7.7.7")
    assert(str(z[15]) == "7.7.7.7")
    assert(str(z[-15]) == "7.7.7.7")
    assert(z.host_no == 1)

    a = IPRange("7.7.7.7", "255.255.255.255")
    b = IPRange("7.7.7.7", "255.255.255.255")
    c = IPRange("7.7.7.8", "255.255.255.255")
    d = IPRange("192.168.1.1", "255.255.255.0")
    e = IPRange("192.168.1.0", "255.255.255.0")
    f = IPRange("192.169.0.0", "255.255.0.0")
    g = IPRange("192.168.2.1", "255.255.255.0")
    h = IPRange("192.168.1.20", "255.255.255.0")
    assert(a == b) # Same IP
    assert(b < c) # CMP single ip values
    assert(a != c) # Not same IP
    assert(d == e) # Check if IP in a range.
    assert(f != e) # Compare two ranges for intersection.
    assert(b < e) # Compare end value of ranges.
    assert(e > b)

    #print(len(f))
    #print(len(e))
    assert(f > e) # Range compare is based on host no, not ip value

    l = [a, c, e]
    assert(d in l)
    assert(b in l)
    assert(g not in l)
    assert(h in l)
    x = IPRange("fe80::9acb:c90e:7bf6:a093%enp3s0", "ffff:ffff:ffff:ffff::/64")
    assert(x.cidr == 64)

    print("Self-tests passed.")
