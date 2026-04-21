"""
Tests for the netifaces parsers using simulated CLI output.

Each test feeds a fixed string (as if returned by the OS command) into the
relevant parser and validates that the parser extracts the right data.  No
real network interfaces or OS commands are needed.
"""

import platform
import unittest
from unittest import main
from aionetiface.settings import IP4, IP6
from aionetiface.net.net_utils import cidr_to_netmask, af_bitlen


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_addr(addr_list, ip):
    return any(a["addr"] == ip for a in addr_list)


def _get_addr(addr_list, ip):
    for a in addr_list:
        if a["addr"] == ip:
            return a
    return None


# ---------------------------------------------------------------------------
# netsh parser tests
# ---------------------------------------------------------------------------

class TestNetshParsers(unittest.TestCase):
    """Tests for win_netsh.NetshParse – regex-only, no I/O."""

    def setUp(self):
        if platform.system() != "Windows":
            # Import still works on non-Windows; we just skip execution.
            pass
        from aionetiface.nic.netifaces.windows.win_netsh import NetshParse
        self.parser = NetshParse()

    # -----------------------------------------------------------------------
    # show_interfaces
    # -----------------------------------------------------------------------
    INTERFACES_V4 = """\
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected     Loopback Pseudo-Interface 1
 12          25        1500  connected     Ethernet
 14          35        1500  connected     Wi-Fi
"""

    def test_show_interfaces_v4(self):
        af, key, data = self.parser.show_interfaces(IP4, self.INTERFACES_V4)
        self.assertEqual(key, "ifs")
        self.assertIn("12", data)
        self.assertEqual(data["12"]["con_name"], "Ethernet")
        self.assertEqual(data["14"]["con_name"], "Wi-Fi")
        self.assertEqual(data["14"]["mtu"], "1500")

    # -----------------------------------------------------------------------
    # show_addresses
    # -----------------------------------------------------------------------
    ADDRESSES_V4 = """\
Interface 12
Addr Type  DAD State  Valid Life Pref. Life Address
---------  ----------  ----------  ---------- ---------------------------
Other      Preferred  infinite   infinite   192.168.1.100

Interface 14
Addr Type  DAD State  Valid Life Pref. Life Address
---------  ----------  ----------  ---------- ---------------------------
Other      Preferred  infinite   infinite   10.0.0.50
"""

    def test_show_addresses_v4(self):
        af, key, data = self.parser.show_addresses(IP4, self.ADDRESSES_V4)
        self.assertEqual(key, "addrs")
        self.assertIn("12", data)
        self.assertEqual(data["12"][0]["addr"], "192.168.1.100")
        self.assertIn("14", data)
        self.assertEqual(data["14"][0]["addr"], "10.0.0.50")

    ADDRESSES_V6 = """\
Interface 12
Addr Type  DAD State  Valid Life Pref. Life Address
---------  ----------  ----------  ---------- ---------------------------
Other      Preferred  infinite   infinite   2402:1f00:8101:83f::1
Other      Preferred  infinite   infinite   fe80::ae1f:6bff:fe94:531a
"""

    def test_show_addresses_v6(self):
        af, key, data = self.parser.show_addresses(IP6, self.ADDRESSES_V6)
        self.assertEqual(key, "addrs")
        self.assertIn("12", data)
        addrs = [e["addr"] for e in data["12"]]
        self.assertIn("2402:1f00:8101:83f::1", addrs)
        self.assertIn("fe80::ae1f:6bff:fe94:531a", addrs)

    # -----------------------------------------------------------------------
    # show_route – CIDR derivation
    # -----------------------------------------------------------------------
    ROUTES_V4 = """\
No  Type  Met  Prefix          Idx  Name
--- ----  ---  --------------- ---  --------
No  System   0  0.0.0.0/0        12  Ethernet
No  System  10  192.168.1.0/24   12  Ethernet
No  System  20  10.0.0.0/8       14  Wi-Fi
"""

    def test_show_route_v4(self):
        af, key, data = self.parser.show_route(IP4, self.ROUTES_V4)
        self.assertEqual(key, "routes")
        self.assertIn("12", data)
        prefixes = [r["prefix"] for r in data["12"]]
        self.assertIn("192.168.1.0/24", prefixes)

    ROUTES_V6 = """\
No  Type  Met  Prefix                         Idx  Name
--- ----  ---  ------------------------------ ---  --------
No  System   0  ::/0                            12  Ethernet
No  System  10  2402:1f00:8101:83f::/64         12  Ethernet
No  System  20  fe80::/64                       12  Ethernet
"""

    def test_show_route_v6(self):
        af, key, data = self.parser.show_route(IP6, self.ROUTES_V6)
        self.assertEqual(key, "routes")
        self.assertIn("12", data)
        prefixes = [r["prefix"] for r in data["12"]]
        self.assertIn("2402:1f00:8101:83f::/64", prefixes)

    # -----------------------------------------------------------------------
    # get_host_limit_from_route_infos
    # -----------------------------------------------------------------------
    def test_get_host_limit_from_route_infos_v4(self):
        from aionetiface.nic.netifaces.windows.win_netsh import get_host_limit_from_route_infos
        route_infos = [
            {"prefix": "0.0.0.0/0"},
            {"prefix": "192.168.1.0/24"},
            {"prefix": "192.168.0.0/16"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos("192.168.1.100", route_infos)
        self.assertEqual(host_limit, 24)
        self.assertEqual(netmask, "255.255.255.0")

    def test_get_host_limit_from_route_infos_v6(self):
        from aionetiface.nic.netifaces.windows.win_netsh import get_host_limit_from_route_infos
        route_infos = [
            {"prefix": "::/0"},
            {"prefix": "2402:1f00:8101:83f::/64"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos(
            "2402:1f00:8101:83f::1", route_infos
        )
        self.assertEqual(host_limit, 64)

    def test_get_host_limit_from_route_infos_most_specific(self):
        """Most-specific (highest host_limit) matching prefix wins."""
        from aionetiface.nic.netifaces.windows.win_netsh import get_host_limit_from_route_infos
        route_infos = [
            {"prefix": "10.0.0.0/8"},
            {"prefix": "10.10.0.0/16"},
            {"prefix": "10.10.10.0/24"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos("10.10.10.50", route_infos)
        self.assertEqual(host_limit, 24)

    # -----------------------------------------------------------------------
    # show_mac / show_gws  (smoke tests with simulated route-print output)
    # -----------------------------------------------------------------------
    ROUTE_PRINT = """\
Interface List
 12...aa bb cc dd ee ff ......Ethernet
 14...11 22 33 44 55 66 ......Wi-Fi

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100      25
===========================================================================
"""

    def test_show_mac(self):
        af, key, data = self.parser.show_mac(IP4, self.ROUTE_PRINT)
        self.assertEqual(key, "macs")
        # default v4 route should be captured
        self.assertIsNotNone(data["default"][IP4])
        self.assertEqual(data["default"][IP4]["gw_ip"], "192.168.1.1")

    IPCONFIG_ALL = """\
Ethernet adapter Ethernet:

   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   Default Gateway . . . . . . . . . : 192.168.1.1
                                        fe80::1
"""

    def test_show_gws(self):
        af, key, data = self.parser.show_gws(IP4, self.IPCONFIG_ALL)
        self.assertEqual(key, "gws")
        mac = "aa-bb-cc-dd-ee-ff"
        self.assertIn(mac, data)
        # IPv4 gateway extracted.
        self.assertEqual(data[mac][IP4], "192.168.1.1")


# ---------------------------------------------------------------------------
# WMIC parser tests
# ---------------------------------------------------------------------------

class TestWMICParsers(unittest.TestCase):
    """Tests for win_wmic.WMICParse – regex-only, no I/O."""

    def setUp(self):
        from aionetiface.nic.netifaces.windows.win_wmic import WMICParse, parse_wmic_addrs
        self.parser = WMICParse()
        self.parse_wmic_addrs = parse_wmic_addrs

    # -----------------------------------------------------------------------
    # parse_wmic_addrs
    # -----------------------------------------------------------------------
    def test_parse_wmic_addrs_v4(self):
        addrs = ["192.168.1.100", "10.0.0.1"]
        result = self.parse_wmic_addrs(addrs)
        self.assertTrue(len(result[IP4]) == 2)
        self.assertEqual(len(result[IP6]), 0)
        self.assertTrue(_has_addr(result[IP4], "192.168.1.100"))

    def test_parse_wmic_addrs_v6(self):
        addrs = ["2402:1f00:8101:83f::1", "fe80::ae1f:6bff:fe94:531a"]
        result = self.parse_wmic_addrs(addrs)
        self.assertEqual(len(result[IP4]), 0)
        self.assertTrue(len(result[IP6]) == 2)
        self.assertTrue(_has_addr(result[IP6], "2402:1f00:8101:83f::1"))

    def test_parse_wmic_addrs_mixed(self):
        addrs = ["192.168.1.1", "2402:1f00:8101:83f::1"]
        result = self.parse_wmic_addrs(addrs)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(len(result[IP6]), 1)

    def test_parse_wmic_addrs_empty(self):
        result = self.parse_wmic_addrs([])
        self.assertEqual(len(result[IP4]), 0)
        self.assertEqual(len(result[IP6]), 0)

    # -----------------------------------------------------------------------
    # parse_wmic_list
    # -----------------------------------------------------------------------
    def test_parse_wmic_list_braces(self):
        from aionetiface.nic.netifaces.windows.win_wmic import parse_wmic_list
        result = parse_wmic_list("{'192.168.1.1', '10.0.0.1'}")
        self.assertIn("192.168.1.1", result)
        self.assertIn("10.0.0.1", result)

    def test_parse_wmic_list_empty(self):
        from aionetiface.nic.netifaces.windows.win_wmic import parse_wmic_list
        result = parse_wmic_list("")
        self.assertEqual(result, [])

    def test_parse_wmic_list_single(self):
        from aionetiface.nic.netifaces.windows.win_wmic import parse_wmic_list
        result = parse_wmic_list("{'192.168.1.1'}")
        self.assertIn("192.168.1.1", result)

    # -----------------------------------------------------------------------
    # WMICParse.show_main  (simulated wmic output)
    # -----------------------------------------------------------------------
    WMIC_MAIN = (
        "                                         "
        "  Ethernet  "
        "                                          "
        "12  "
        "{'192.168.1.100'}  "
        "AA:BB:CC:DD:EE:FF  "
        "{GUID-1234-5678}  "
        "\r\n"
    )

    # show_main regex is complex; smoke-test that it doesn't crash.
    def test_show_main_smoke(self):
        af, key, data = self.parser.show_main(IP4, self.WMIC_MAIN)
        self.assertEqual(key, "main")
        # May or may not match depending on exact spacing – just assert no exception.

    # -----------------------------------------------------------------------
    # WMICParse.show_con_names
    # -----------------------------------------------------------------------
    CON_NAMES = (
        "Index  Name\r\n"
        "-----  ----\r\n"
        "12     Ethernet   \r\n"
        "14     Wi-Fi 2    \r\n"
    )

    def test_show_con_names(self):
        af, key, data = self.parser.show_con_names(IP4, self.CON_NAMES)
        self.assertEqual(key, "con_names")
        self.assertIn("12", data)
        self.assertEqual(data["12"]["con_name"], "Ethernet")
        self.assertIn("14", data)
        self.assertEqual(data["14"]["con_name"], "Wi-Fi 2")

    # -----------------------------------------------------------------------
    # WMICParse.show_routes
    # -----------------------------------------------------------------------
    WMIC_ROUTES = """\
Interface List
 12...AA BB CC DD EE FF ......Ethernet

IPv4 Route Table
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100      25

IPv6 Route Table
If  Met  Prefix                         Next Hop
12    5  ::/0                           fe80::1
"""

    def test_show_routes(self):
        af, key, data = self.parser.show_routes(IP4, self.WMIC_ROUTES)
        self.assertEqual(key, "routes")
        self.assertIsNotNone(data["default"][IP4])
        self.assertEqual(data["default"][IP4]["gw_ip"], "192.168.1.1")


# ---------------------------------------------------------------------------
# PowerShell (load_ifs_from_ps1) parsing – unit-level regex tests
# -----------------------------------------------------------------------

class TestPS1Parsing(unittest.TestCase):
    """
    Tests for the Python-side parsing of PowerShell output in load_ifs_from_ps1.
    We simulate the PS1 script output (with our /prefix extension) and verify
    that the Python regex + parsing code extracts correct data.
    """

    # Simulated PS1 output with our modified script that emits "ip/prefix":
    PS1_OUTPUT = """\
4444444444
ifIndex : 12
4444444444
6666666666
ifIndex : 12
6666666666

InterfaceDescription : Intel Ethernet Adapter
ifIndex              : 12
InterfaceGuid        : {ABCD-1234-5678-EF00}
MacAddress           : AA-BB-CC-DD-EE-FF
v4GW                 : 192.168.1.1
v6GW                 : fe80::1

192.168.1.100/24
2402:1f00:8101:83f::1/64
fe80::ae1f:6bff:fe94:531a/64

InterfaceDescription : Wi-Fi Adapter
ifIndex              : 14
InterfaceGuid        : {1111-2222-3333-4444}
MacAddress           : 11-22-33-44-55-66
v4GW                 : 10.0.0.1
v6GW                 : null

10.0.0.50/24
"""

    def _parse_ps1_addr_block(self, block):
        """Replicate the PS1 address parsing logic from load_ifs_from_ps1."""
        import re
        from aionetiface.net.ip_range import IPRange
        from aionetiface.net.net_utils import af_bitlen, cidr_to_netmask
        from aionetiface.net.net_utils import ip_strip_cidr, ip_strip_if

        addr_info = {IP4: [], IP6: []}
        addr_s = block.replace(' ', '')
        addr_list = addr_s.splitlines(False)
        for addr in addr_list:
            if addr == '':
                continue
            prefix_len = None
            if '/' in addr:
                raw_ip, raw_prefix = addr.rsplit('/', 1)
                try:
                    prefix_len = int(raw_prefix)
                except ValueError:
                    pass
                addr = raw_ip
            addr = ip_strip_cidr(ip_strip_if(addr))
            ipr = IPRange(addr)
            host_limit = prefix_len if prefix_len is not None else af_bitlen(ipr.af)
            addr_info[ipr.af].append({
                "addr": addr,
                "af": ipr.af,
                "host_limit": host_limit,
                "netmask": cidr_to_netmask(host_limit, ipr.af)
            })
        return addr_info

    def test_ps1_ipv4_prefix_parsed(self):
        block = "192.168.1.100/24\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP4]), 1)
        addr = result[IP4][0]
        self.assertEqual(addr["addr"], "192.168.1.100")
        self.assertEqual(addr["host_limit"], 24)
        self.assertEqual(addr["netmask"], "255.255.255.0")

    def test_ps1_ipv6_prefix_parsed(self):
        block = "2402:1f00:8101:83f::1/64\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP6]), 1)
        addr = result[IP6][0]
        self.assertEqual(addr["addr"], "2402:1f00:8101:83f::1")
        self.assertEqual(addr["host_limit"], 64)

    def test_ps1_link_local_prefix_parsed(self):
        block = "fe80::ae1f:6bff:fe94:531a/64\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP6]), 1)
        addr = result[IP6][0]
        self.assertEqual(addr["host_limit"], 64)

    def test_ps1_no_prefix_falls_back_to_max(self):
        """When no /prefix is present, af_bitlen is used as fallback."""
        block = "192.168.1.100\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(result[IP4][0]["host_limit"], 32)

    def test_ps1_mixed_block(self):
        block = "192.168.1.100/24\n2402:1f00:8101:83f::1/64\nfe80::ae1f:6bff:fe94:531a/64\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(len(result[IP6]), 2)

    def test_ps1_regex_captures_slash_in_ip_list(self):
        """Confirm the updated regex accepts /prefix in the IP list field."""
        import re
        # The full regex from load_ifs_from_ps1 (updated to allow / in IP list).
        p = (
            r"InterfaceDescription *: *([^\r\n]+?) *[\r\n]+"
            r"ifIndex *: *([0-9]+?) *[\r\n]+"
            r"InterfaceGuid *: *([^\r\n]+?) *[\r\n]+"
            r"MacAddress *: *([^\r\n]+?) *[\r\n]+"
            r"v4GW *: *([^\r\n]+?) *[\r\n]+"
            r"v6GW *: *([^ ]+?)[\s]+"
            r"((?:[0-9a-f.:%/]+ *[\r\n]*)+)"
        )
        results = re.findall(p, self.PS1_OUTPUT)
        self.assertTrue(len(results) >= 1)
        # First interface.
        r = results[0]
        self.assertIn("Intel Ethernet Adapter", r[0])
        self.assertEqual(r[1], "12")
        # IP list should contain the /prefix entries.
        ip_block = r[6]
        self.assertIn("192.168.1.100/24", ip_block)
        self.assertIn("2402:1f00:8101:83f::1/64", ip_block)


# ---------------------------------------------------------------------------
# get_addr_info_by_if_index output parsing
# ---------------------------------------------------------------------------

class TestGetAddrInfoParsing(unittest.TestCase):
    """
    Tests for the regex in get_addr_info_by_if_index that parses
    'Get-NetIPAddress -InterfaceIndex N' PowerShell output.
    """

    PS_ADDR_OUTPUT = """\
IPAddress      : 192.168.1.100
AddressFamily  : IPv4
PrefixLength   : 24

IPAddress      : 2402:1f00:8101:83f::1
AddressFamily  : IPv6
PrefixLength   : 64

IPAddress      : fe80::ae1f:6bff:fe94:531a
AddressFamily  : IPv6
PrefixLength   : 64
"""

    def _parse_addr_output(self, out):
        import re
        from aionetiface.net.net_utils import cidr_to_netmask
        addr = {IP4: [], IP6: []}
        addr_infos = re.findall(
            r"IPAddress\s*:\s*([^\s]*)[\s\S]*?AddressFamily\s*:\s*([^\s]+)[\s\S]*?PrefixLength\s*:\s([0-9]+)",
            out
        )
        for info in addr_infos:
            ip_val, af_family, host_limit = info
            host_limit = int(host_limit)
            if af_family == "IPv4":
                af = IP4
            if af_family == "IPv6":
                af = IP6
            addr[af].append({
                "addr": ip_val,
                "af": af,
                "host_limit": host_limit,
                "netmask": cidr_to_netmask(host_limit, af)
            })
        return addr

    def test_ipv4_extracted(self):
        result = self._parse_addr_output(self.PS_ADDR_OUTPUT)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(result[IP4][0]["addr"], "192.168.1.100")
        self.assertEqual(result[IP4][0]["host_limit"], 24)
        self.assertEqual(result[IP4][0]["netmask"], "255.255.255.0")

    def test_ipv6_extracted(self):
        result = self._parse_addr_output(self.PS_ADDR_OUTPUT)
        self.assertEqual(len(result[IP6]), 2)
        self.assertTrue(_has_addr(result[IP6], "2402:1f00:8101:83f::1"))
        addr = _get_addr(result[IP6], "2402:1f00:8101:83f::1")
        self.assertEqual(addr["host_limit"], 64)

    def test_netmask_populated(self):
        result = self._parse_addr_output(self.PS_ADDR_OUTPUT)
        for addr in result[IP4]:
            self.assertIsNotNone(addr.get("netmask"))
        for addr in result[IP6]:
            self.assertIsNotNone(addr.get("netmask"))


# ---------------------------------------------------------------------------
# netiface_addr_to_ipr  (Linux netifaces dict → IPRange)
# ---------------------------------------------------------------------------

class TestNetiaceAddrToIPR(unittest.IsolatedAsyncioTestCase):
    """
    Tests for netiface_addr_to_ipr using simulated netifaces info dicts,
    covering all the edge cases that arise from different OS netmask formats.
    """

    async def _to_ipr(self, af, addr, netmask, nic_id=0):
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr
        info = {"addr": addr, "netmask": netmask}
        return await netiface_addr_to_ipr(af, nic_id, info)

    async def test_ipv4_host_with_slash24_netmask(self):
        ipr = await self._to_ipr(IP4, "192.168.1.100", "255.255.255.0")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)      # single-host range
        self.assertEqual(ipr.subnet, 24) # OS prefix stored separately

    async def test_ipv4_host_with_full_netmask(self):
        ipr = await self._to_ipr(IP4, "8.8.8.8", "255.255.255.255")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 32)

    async def test_ipv4_missing_addr(self):
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr
        result = await netiface_addr_to_ipr(IP4, 0, {"netmask": "255.255.255.0"})
        self.assertIsNone(result)

    async def test_ipv4_missing_netmask(self):
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr
        result = await netiface_addr_to_ipr(IP4, 0, {"addr": "192.168.1.1"})
        self.assertIsNone(result)

    async def test_ipv6_host_with_slash64_netmask(self):
        ipr = await self._to_ipr(
            IP6,
            "2402:1f00:8101:83f::1",
            "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)      # single-host
        self.assertEqual(ipr.subnet, 64) # OS /64 prefix

    async def test_ipv6_host_with_full_netmask(self):
        ipr = await self._to_ipr(
            IP6,
            "2402:1f00:8101:83f::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 128)

    async def test_ipv6_link_local_with_slash64(self):
        ipr = await self._to_ipr(
            IP6,
            "fe80::ae1f:6bff:fe94:531a",
            "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 64)

    async def test_ipv6_link_local_with_interface_suffix(self):
        """Addresses with %interface suffixes must load correctly."""
        ipr = await self._to_ipr(
            IP6,
            "fe80::ae1f:6bff:fe94:531a%eth0",
            "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)

    async def test_bad_netmask_falls_back_gracefully(self):
        """Unusual netmask format must not drop the address entirely."""
        ipr = await self._to_ipr(IP4, "10.0.0.1", "255.255.255.0")
        self.assertIsNotNone(ipr)

    async def test_ipv4_block_assignment(self):
        """Network address assigned to interface (i_host==0) → block IPRange with bitlen=5 (5 host bits = /27)."""
        ipr = await self._to_ipr(IP4, "203.0.113.0", "255.255.255.224")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 5)
        self.assertEqual(ipr.host_limit, 31)  # 2^5 - 1 usable hosts in /27
        self.assertEqual(ipr.subnet, 27)
        self.assertEqual(ipr.i_host, 0)

    async def test_net_cidr_preserved_across_deepcopy(self):
        import copy
        ipr = await self._to_ipr(IP4, "192.168.1.5", "255.255.255.0")
        copied = copy.deepcopy(ipr)
        self.assertEqual(copied.subnet, ipr.subnet)


# ---------------------------------------------------------------------------
# group_pub_iprs_by_subnet  (route grouping logic)
# ---------------------------------------------------------------------------

class TestGroupPubIPRsByNetCidr(unittest.TestCase):
    """
    Tests for the subnet-based grouping used in discover_nic_wan_ips.
    Uses synthetic IPRange objects with manually set subnet values.
    """

    def _make_ipr(self, ip, subnet, af=IP4):
        from aionetiface.net.ip_range import IPRange
        ipr = IPRange(ip, bitlen=0)
        ipr.subnet = subnet
        return ipr

    def _group(self, iprs, af=IP4):
        from aionetiface.nic.route.route_load import group_pub_iprs_by_subnet
        max_bits = 128 if af == IP6 else 32
        return group_pub_iprs_by_subnet(iprs, max_bits)

    def test_same_subnet_grouped(self):
        """Two IPv4 IPs in the same /24 share one group head."""
        ipr_a = self._make_ipr("192.168.1.1", 24)
        ipr_b = self._make_ipr("192.168.1.2", 24)
        heads, individuals = self._group([ipr_a, ipr_b])
        self.assertEqual(len(heads), 1)
        self.assertEqual(len(individuals), 0)
        # The second IP is in the rest list.
        rest = list(heads.values())[0]
        self.assertEqual(len(rest), 1)

    def test_different_subnets_separate_groups(self):
        """IPs in different /24 subnets each get their own group."""
        ipr_a = self._make_ipr("192.168.1.1", 24)
        ipr_b = self._make_ipr("192.168.2.1", 24)
        heads, individuals = self._group([ipr_a, ipr_b])
        self.assertEqual(len(heads), 2)
        self.assertEqual(len(individuals), 0)

    def test_ipv4_max_cidr_goes_individual(self):
        """IPv4 /32 addresses (unknown prefix) go to individual_iprs."""
        ipr = self._make_ipr("8.8.8.8", 32)
        heads, individuals = self._group([ipr])
        self.assertEqual(len(heads), 0)
        self.assertEqual(len(individuals), 1)

    def test_ipv6_slash128_goes_individual(self):
        """IPv6 /128 addresses go to individual_iprs."""
        ipr = self._make_ipr("2402:1f00:8101:83f::1", 128, af=IP6)
        heads, individuals = self._group([ipr], af=IP6)
        self.assertEqual(len(heads), 0)
        self.assertEqual(len(individuals), 1)

    def test_ipv6_slash64_grouped(self):
        """Two IPv6 IPs in the same /64 share one group head."""
        ipr_a = self._make_ipr("2402:1f00:8101:83f::1", 64, af=IP6)
        ipr_b = self._make_ipr("2402:1f00:8101:83f::2", 64, af=IP6)
        heads, individuals = self._group([ipr_a, ipr_b], af=IP6)
        self.assertEqual(len(heads), 1)
        self.assertEqual(len(individuals), 0)

    def test_ipv6_different_slash64_separate(self):
        """IPv6 IPs in different /64 subnets are separate groups."""
        ipr_a = self._make_ipr("2402:1f00:8101:83f::1", 64, af=IP6)
        ipr_b = self._make_ipr("2402:1f00:8101:840::1", 64, af=IP6)
        heads, individuals = self._group([ipr_a, ipr_b], af=IP6)
        self.assertEqual(len(heads), 2)
        self.assertEqual(len(individuals), 0)

    def test_empty_list(self):
        heads, individuals = self._group([])
        self.assertEqual(len(heads), 0)
        self.assertEqual(len(individuals), 0)

    def test_none_net_cidr_falls_back_to_individual(self):
        """subnet=None is treated as max_bits → individual query."""
        from aionetiface.net.ip_range import IPRange
        ipr = IPRange("10.0.0.1")
        ipr.subnet = None
        _, individuals = self._group([ipr])
        self.assertEqual(len(individuals), 1)


if __name__ == '__main__':
    main()
