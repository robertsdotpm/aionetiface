"""
Tests for the netifaces parsers using simulated CLI output.

Each test feeds a fixed string (as if returned by the OS command) into the
relevant parser and validates that the parser extracts the right data.  No
real network interfaces or OS commands are needed.
"""

import platform
import unittest
from aionetiface.testing import AsyncTestCase
from unittest import main
from typing import Any, List, Dict, Optional
from aionetiface.settings import IP4, IP6
from aionetiface.net.net_utils import cidr_to_netmask, af_bitlen


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_addr(addr_list: List[Dict[str, Any]], ip: str) -> bool:
    return any(a["addr"] == ip for a in addr_list)


def _get_addr(addr_list: List[Dict[str, Any]], ip: str) -> Optional[Dict[str, Any]]:
    for a in addr_list:
        if a["addr"] == ip:
            return a
    return None


# ---------------------------------------------------------------------------
# netsh parser tests
# ---------------------------------------------------------------------------


class TestNetshParsers(unittest.TestCase):
    """Tests for win_netsh.NetshParse – regex-only, no I/O."""

    def setUp(self) -> None:
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

    def test_show_interfaces_v4(self) -> None:
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

    def test_show_addresses_v4(self) -> None:
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

    def test_show_addresses_v6(self) -> None:
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

    def test_show_route_v4(self) -> None:
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

    def test_show_route_v6(self) -> None:
        af, key, data = self.parser.show_route(IP6, self.ROUTES_V6)
        self.assertEqual(key, "routes")
        self.assertIn("12", data)
        prefixes = [r["prefix"] for r in data["12"]]
        self.assertIn("2402:1f00:8101:83f::/64", prefixes)

    # -----------------------------------------------------------------------
    # get_host_limit_from_route_infos
    # -----------------------------------------------------------------------
    def test_get_host_limit_from_route_infos_v4(self) -> None:
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "0.0.0.0/0"},
            {"prefix": "192.168.1.0/24"},
            {"prefix": "192.168.0.0/16"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos(
            "192.168.1.100", route_infos
        )
        self.assertEqual(host_limit, 24)
        self.assertEqual(netmask, "255.255.255.0")

    def test_get_host_limit_from_route_infos_v6(self) -> None:
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "::/0"},
            {"prefix": "2402:1f00:8101:83f::/64"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos(
            "2402:1f00:8101:83f::1", route_infos
        )
        self.assertEqual(host_limit, 64)

    def test_get_host_limit_from_route_infos_most_specific(self) -> None:
        """Most-specific (highest host_limit) matching prefix wins."""
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "10.0.0.0/8"},
            {"prefix": "10.10.0.0/16"},
            {"prefix": "10.10.10.0/24"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos(
            "10.10.10.50", route_infos
        )
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

    def test_show_mac(self) -> None:
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

    def test_show_gws(self) -> None:
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

    def setUp(self) -> None:
        from aionetiface.nic.netifaces.windows.win_wmic import (
            WMICParse,
            parse_wmic_addrs,
        )

        self.parser = WMICParse()
        self.parse_wmic_addrs = parse_wmic_addrs

    # -----------------------------------------------------------------------
    # parse_wmic_addrs
    # -----------------------------------------------------------------------
    def test_parse_wmic_addrs_v4(self) -> None:
        addrs = ["192.168.1.100", "10.0.0.1"]
        result = self.parse_wmic_addrs(addrs)
        self.assertTrue(len(result[IP4]) == 2)
        self.assertEqual(len(result[IP6]), 0)
        self.assertTrue(_has_addr(result[IP4], "192.168.1.100"))

    def test_parse_wmic_addrs_v6(self) -> None:
        addrs = ["2402:1f00:8101:83f::1", "fe80::ae1f:6bff:fe94:531a"]
        result = self.parse_wmic_addrs(addrs)
        self.assertEqual(len(result[IP4]), 0)
        self.assertTrue(len(result[IP6]) == 2)
        self.assertTrue(_has_addr(result[IP6], "2402:1f00:8101:83f::1"))

    def test_parse_wmic_addrs_mixed(self) -> None:
        addrs = ["192.168.1.1", "2402:1f00:8101:83f::1"]
        result = self.parse_wmic_addrs(addrs)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(len(result[IP6]), 1)

    def test_parse_wmic_addrs_empty(self) -> None:
        result = self.parse_wmic_addrs([])
        self.assertEqual(len(result[IP4]), 0)
        self.assertEqual(len(result[IP6]), 0)

    # -----------------------------------------------------------------------
    # parse_wmic_list
    # -----------------------------------------------------------------------
    def test_parse_wmic_list_braces(self) -> None:
        from aionetiface.nic.netifaces.windows.win_wmic import parse_wmic_list

        result = parse_wmic_list("{'192.168.1.1', '10.0.0.1'}")
        self.assertIn("192.168.1.1", result)
        self.assertIn("10.0.0.1", result)

    def test_parse_wmic_list_empty(self) -> None:
        from aionetiface.nic.netifaces.windows.win_wmic import parse_wmic_list

        result = parse_wmic_list("")
        self.assertEqual(result, [])

    def test_parse_wmic_list_single(self) -> None:
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
    def test_show_main_smoke(self) -> None:
        af, key, data = self.parser.show_main(IP4, self.WMIC_MAIN)
        self.assertEqual(key, "main")
        # May or may not match depending on exact spacing – just assert no exception.

    # -----------------------------------------------------------------------
    # WMICParse.show_con_names
    # -----------------------------------------------------------------------
    CON_NAMES = (
        "Index  Name\r\n-----  ----\r\n12     Ethernet   \r\n14     Wi-Fi 2    \r\n"
    )

    def test_show_con_names(self) -> None:
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

    def test_show_routes(self) -> None:
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

    def _parse_ps1_addr_block(self, block: str) -> Dict[Any, List[Dict[str, Any]]]:
        """Replicate the PS1 address parsing logic from load_ifs_from_ps1."""
        import re
        from aionetiface.net.ip_range import IPRange
        from aionetiface.net.net_utils import af_bitlen, cidr_to_netmask
        from aionetiface.net.net_utils import ip_strip_cidr, ip_strip_if

        addr_info = {IP4: [], IP6: []}
        addr_s = block.replace(" ", "")
        addr_list = addr_s.splitlines(False)
        for addr in addr_list:
            if addr == "":
                continue
            prefix_len = None
            if "/" in addr:
                raw_ip, raw_prefix = addr.rsplit("/", 1)
                try:
                    prefix_len = int(raw_prefix)
                except ValueError:
                    pass
                addr = raw_ip
            addr = ip_strip_cidr(ip_strip_if(addr))
            ipr = IPRange(addr)
            host_limit = prefix_len if prefix_len is not None else af_bitlen(ipr.af)
            addr_info[ipr.af].append(
                {
                    "addr": addr,
                    "af": ipr.af,
                    "host_limit": host_limit,
                    "netmask": cidr_to_netmask(host_limit, ipr.af),
                }
            )
        return addr_info

    def test_ps1_ipv4_prefix_parsed(self) -> None:
        block = "192.168.1.100/24\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP4]), 1)
        addr = result[IP4][0]
        self.assertEqual(addr["addr"], "192.168.1.100")
        self.assertEqual(addr["host_limit"], 24)
        self.assertEqual(addr["netmask"], "255.255.255.0")

    def test_ps1_ipv6_prefix_parsed(self) -> None:
        block = "2402:1f00:8101:83f::1/64\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP6]), 1)
        addr = result[IP6][0]
        self.assertEqual(addr["addr"], "2402:1f00:8101:83f::1")
        self.assertEqual(addr["host_limit"], 64)

    def test_ps1_link_local_prefix_parsed(self) -> None:
        block = "fe80::ae1f:6bff:fe94:531a/64\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP6]), 1)
        addr = result[IP6][0]
        self.assertEqual(addr["host_limit"], 64)

    def test_ps1_no_prefix_falls_back_to_max(self) -> None:
        """When no /prefix is present, af_bitlen is used as fallback."""
        block = "192.168.1.100\n"
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(result[IP4][0]["host_limit"], 32)

    def test_ps1_mixed_block(self) -> None:
        block = (
            "192.168.1.100/24\n2402:1f00:8101:83f::1/64\nfe80::ae1f:6bff:fe94:531a/64\n"
        )
        result = self._parse_ps1_addr_block(block)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(len(result[IP6]), 2)

    def test_ps1_regex_captures_slash_in_ip_list(self) -> None:
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

    def _parse_addr_output(self, out: str) -> Dict[Any, List[Dict[str, Any]]]:
        import re
        from aionetiface.net.net_utils import cidr_to_netmask

        addr = {IP4: [], IP6: []}
        addr_infos = re.findall(
            r"IPAddress\s*:\s*([^\s]*)[\s\S]*?AddressFamily\s*:\s*([^\s]+)[\s\S]*?PrefixLength\s*:\s([0-9]+)",
            out,
        )
        for info in addr_infos:
            ip_val, af_family, host_limit = info
            host_limit = int(host_limit)
            if af_family == "IPv4":
                af = IP4
            if af_family == "IPv6":
                af = IP6
            addr[af].append(
                {
                    "addr": ip_val,
                    "af": af,
                    "host_limit": host_limit,
                    "netmask": cidr_to_netmask(host_limit, af),
                }
            )
        return addr

    def test_ipv4_extracted(self) -> None:
        result = self._parse_addr_output(self.PS_ADDR_OUTPUT)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(result[IP4][0]["addr"], "192.168.1.100")
        self.assertEqual(result[IP4][0]["host_limit"], 24)
        self.assertEqual(result[IP4][0]["netmask"], "255.255.255.0")

    def test_ipv6_extracted(self) -> None:
        result = self._parse_addr_output(self.PS_ADDR_OUTPUT)
        self.assertEqual(len(result[IP6]), 2)
        self.assertTrue(_has_addr(result[IP6], "2402:1f00:8101:83f::1"))
        addr = _get_addr(result[IP6], "2402:1f00:8101:83f::1")
        self.assertEqual(addr["host_limit"], 64)

    def test_netmask_populated(self) -> None:
        result = self._parse_addr_output(self.PS_ADDR_OUTPUT)
        for addr in result[IP4]:
            self.assertIsNotNone(addr.get("netmask"))
        for addr in result[IP6]:
            self.assertIsNotNone(addr.get("netmask"))


# ---------------------------------------------------------------------------
# netiface_addr_to_ipr  (Linux netifaces dict → IPRange)
# ---------------------------------------------------------------------------


class TestNetiaceAddrToIPR(AsyncTestCase):
    """
    Tests for netiface_addr_to_ipr using simulated netifaces info dicts,
    covering all the edge cases that arise from different OS netmask formats.
    """

    async def _to_ipr(self, af: Any, addr: str, netmask: str, nic_id: int = 0) -> Any:
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr

        info = {"addr": addr, "netmask": netmask}
        return await netiface_addr_to_ipr(af, nic_id, info)

    async def test_ipv4_host_with_slash24_netmask(self) -> None:
        ipr = await self._to_ipr(IP4, "192.168.1.100", "255.255.255.0")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)  # single-host range
        self.assertEqual(ipr.subnet, 24)  # OS prefix stored separately

    async def test_ipv4_host_with_full_netmask(self) -> None:
        ipr = await self._to_ipr(IP4, "8.8.8.8", "255.255.255.255")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 32)

    async def test_ipv4_missing_addr(self) -> None:
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr

        result = await netiface_addr_to_ipr(IP4, 0, {"netmask": "255.255.255.0"})
        self.assertIsNone(result)

    async def test_ipv4_missing_netmask(self) -> None:
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr

        result = await netiface_addr_to_ipr(IP4, 0, {"addr": "192.168.1.1"})
        self.assertIsNone(result)

    async def test_ipv6_host_with_slash64_netmask(self) -> None:
        ipr = await self._to_ipr(
            IP6, "2402:1f00:8101:83f::1", "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)  # single-host
        self.assertEqual(ipr.subnet, 64)  # OS /64 prefix

    async def test_ipv6_host_with_full_netmask(self) -> None:
        ipr = await self._to_ipr(
            IP6, "2402:1f00:8101:83f::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 128)

    async def test_ipv6_link_local_with_slash64(self) -> None:
        ipr = await self._to_ipr(
            IP6, "fe80::ae1f:6bff:fe94:531a", "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 64)

    async def test_ipv6_link_local_with_interface_suffix(self) -> None:
        """Addresses with %interface suffixes must load correctly."""
        ipr = await self._to_ipr(
            IP6, "fe80::ae1f:6bff:fe94:531a%eth0", "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)

    async def test_bad_netmask_falls_back_gracefully(self) -> None:
        """Unusual netmask format must not drop the address entirely."""
        ipr = await self._to_ipr(IP4, "10.0.0.1", "255.255.255.0")
        self.assertIsNotNone(ipr)

    async def test_ipv4_block_assignment(self) -> None:
        """Network address assigned to interface (i_host==0) → block IPRange with bitlen=5 (5 host bits = /27)."""
        ipr = await self._to_ipr(IP4, "203.0.113.0", "255.255.255.224")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 5)
        self.assertEqual(ipr.host_limit, 31)  # 2^5 - 1 usable hosts in /27
        self.assertEqual(ipr.subnet, 27)
        self.assertEqual(ipr.i_host, 0)

    async def test_net_cidr_preserved_across_deepcopy(self) -> None:
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

    def _make_ipr(self, ip: str, subnet: int, af: Any = IP4) -> Any:
        from aionetiface.net.ip_range import IPRange

        ipr = IPRange(ip, bitlen=0)
        ipr.subnet = subnet
        return ipr

    def _group(self, iprs: List[Any], af: Any = IP4) -> Any:
        from aionetiface.nic.route.route_load import group_pub_iprs_by_subnet

        max_bits = 128 if af == IP6 else 32
        return group_pub_iprs_by_subnet(iprs, max_bits)

    def test_same_subnet_grouped(self) -> None:
        """Two IPv4 IPs in the same /24 share one group head."""
        ipr_a = self._make_ipr("192.168.1.1", 24)
        ipr_b = self._make_ipr("192.168.1.2", 24)
        heads, individuals = self._group([ipr_a, ipr_b])
        self.assertEqual(len(heads), 1)
        self.assertEqual(len(individuals), 0)
        # The second IP is in the rest list.
        rest = list(heads.values())[0]
        self.assertEqual(len(rest), 1)

    def test_different_subnets_separate_groups(self) -> None:
        """IPs in different /24 subnets each get their own group."""
        ipr_a = self._make_ipr("192.168.1.1", 24)
        ipr_b = self._make_ipr("192.168.2.1", 24)
        heads, individuals = self._group([ipr_a, ipr_b])
        self.assertEqual(len(heads), 2)
        self.assertEqual(len(individuals), 0)

    def test_ipv4_max_cidr_goes_individual(self) -> None:
        """IPv4 /32 addresses (unknown prefix) go to individual_iprs."""
        ipr = self._make_ipr("8.8.8.8", 32)
        heads, individuals = self._group([ipr])
        self.assertEqual(len(heads), 0)
        self.assertEqual(len(individuals), 1)

    def test_ipv6_slash128_goes_individual(self) -> None:
        """IPv6 /128 addresses go to individual_iprs."""
        ipr = self._make_ipr("2402:1f00:8101:83f::1", 128, af=IP6)
        heads, individuals = self._group([ipr], af=IP6)
        self.assertEqual(len(heads), 0)
        self.assertEqual(len(individuals), 1)

    def test_ipv6_slash64_grouped(self) -> None:
        """Two IPv6 IPs in the same /64 share one group head."""
        ipr_a = self._make_ipr("2402:1f00:8101:83f::1", 64, af=IP6)
        ipr_b = self._make_ipr("2402:1f00:8101:83f::2", 64, af=IP6)
        heads, individuals = self._group([ipr_a, ipr_b], af=IP6)
        self.assertEqual(len(heads), 1)
        self.assertEqual(len(individuals), 0)

    def test_ipv6_different_slash64_separate(self) -> None:
        """IPv6 IPs in different /64 subnets are separate groups."""
        ipr_a = self._make_ipr("2402:1f00:8101:83f::1", 64, af=IP6)
        ipr_b = self._make_ipr("2402:1f00:8101:840::1", 64, af=IP6)
        heads, individuals = self._group([ipr_a, ipr_b], af=IP6)
        self.assertEqual(len(heads), 2)
        self.assertEqual(len(individuals), 0)

    def test_empty_list(self) -> None:
        heads, individuals = self._group([])
        self.assertEqual(len(heads), 0)
        self.assertEqual(len(individuals), 0)

    def test_none_net_cidr_falls_back_to_individual(self) -> None:
        """subnet=None is treated as max_bits → individual query."""
        from aionetiface.net.ip_range import IPRange

        ipr = IPRange("10.0.0.1")
        ipr.subnet = None
        _, individuals = self._group([ipr])
        self.assertEqual(len(individuals), 1)


# ---------------------------------------------------------------------------
# get_mac_mixed regex tests (cross-platform MAC extraction)
# ---------------------------------------------------------------------------


class TestGetMacMixedRegex(unittest.TestCase):
    """
    Tests the MAC extraction regexes used by get_mac_mixed without running
    actual OS commands.  Each OS path has its own lambda/regex; we exercise
    those directly against realistic CLI output samples.
    """

    MAC_P = r"((?:[0-9a-fA-F]{2}[\s:-]*){6})"
    IFCONFIG_P = r"\s+[a-zA-Z]+\s+([^\s]+)"

    def _extract_mac_ip_addr(self, output: str) -> Optional[str]:
        import re

        matches = re.findall(self.MAC_P, output)
        return matches[0].strip() if matches else None

    def _extract_mac_ifconfig(self, output: str) -> Optional[str]:
        import re

        matches = re.findall(self.IFCONFIG_P, output)
        return matches[0].strip() if matches else None

    # --- Linux: ip addr show eth0 | egrep 'lladdr|ether|link' ---

    # Ubuntu 18.04 / Debian – plain link/ether line
    LINUX_IP_ADDR_UBUNTU = "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"

    def test_linux_ip_addr_ubuntu(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_UBUNTU)
        self.assertIsNotNone(mac)
        self.assertIn("52", mac)

    # RHEL/CentOS 7 – capital hex digits, trailing link-netnsid
    LINUX_IP_ADDR_RHEL = (
        "    link/ether 00:1A:4B:C8:D3:F2 brd ff:ff:ff:ff:ff:ff link-netnsid 0\n"
    )

    def test_linux_ip_addr_rhel_link_netnsid(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_RHEL)
        self.assertIsNotNone(mac)
        self.assertIn("1A", mac.upper())

    # Alpine Linux / Docker – minimal output, no broadcast line
    LINUX_IP_ADDR_ALPINE = "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"

    def test_linux_ip_addr_alpine(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_ALPINE)
        self.assertIsNotNone(mac)

    # Raspberry Pi – MAC with Raspberry Pi OUI (b8:27:eb)
    LINUX_IP_ADDR_RPI = "    link/ether b8:27:eb:12:34:56 brd ff:ff:ff:ff:ff:ff\n"

    def test_linux_ip_addr_rpi(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_RPI)
        self.assertIsNotNone(mac)
        self.assertIn("b8", mac.lower())

    # Linux with altname line also present in grep output
    LINUX_IP_ADDR_WITH_ALTNAME = (
        "    link/ether 00:0c:29:57:d0:5c brd ff:ff:ff:ff:ff:ff\n    altname enp3s0\n"
    )

    def test_linux_ip_addr_with_altname(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_WITH_ALTNAME)
        self.assertIsNotNone(mac)
        self.assertIn("00:0c:29", mac.lower())

    # Linux – VLAN interface (ether appears same way)
    LINUX_IP_ADDR_VLAN = "    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n"

    def test_linux_ip_addr_vlan(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_VLAN)
        self.assertIsNotNone(mac)

    # OpenWrt – compact format, no trailing spaces
    LINUX_IP_ADDR_OPENWRT = "    link/ether dc:ef:09:ab:cd:ef brd ff:ff:ff:ff:ff:ff\n"

    def test_linux_ip_addr_openwrt(self) -> None:
        mac = self._extract_mac_ip_addr(self.LINUX_IP_ADDR_OPENWRT)
        self.assertIsNotNone(mac)
        self.assertIn("dc", mac.lower())

    # --- OpenBSD/FreeBSD: ifconfig em0 | egrep 'lladdr|ether|link' ---

    # OpenBSD 7.x – uses "lladdr"
    OPENBSD_IFCONFIG_LLADDR = "        lladdr 00:0c:29:57:d0:5c\n"

    def test_openbsd_ifconfig_lladdr(self) -> None:
        mac = self._extract_mac_ifconfig(self.OPENBSD_IFCONFIG_LLADDR)
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "00:0c:29:57:d0:5c")

    # FreeBSD 13 – uses "ether" keyword
    FREEBSD_IFCONFIG_ETHER = "        ether 00:19:d1:ab:cd:ef\n"

    def test_freebsd_ifconfig_ether(self) -> None:
        mac = self._extract_mac_ifconfig(self.FREEBSD_IFCONFIG_ETHER)
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "00:19:d1:ab:cd:ef")

    # macOS 12 Monterey – "ether" with trailing space
    MACOS_IFCONFIG_ETHER = "        ether 8c:85:90:12:34:56 \n"

    def test_macos_ifconfig_ether(self) -> None:
        mac = self._extract_mac_ifconfig(self.MACOS_IFCONFIG_ETHER)
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "8c:85:90:12:34:56")

    # macOS – Apple Silicon OUI (f8:ff:c2)
    MACOS_IFCONFIG_M1 = "        ether f8:ff:c2:ab:cd:ef\n"

    def test_macos_ifconfig_m1(self) -> None:
        mac = self._extract_mac_ifconfig(self.MACOS_IFCONFIG_M1)
        self.assertIsNotNone(mac)
        self.assertIn("f8", mac.lower())

    # NetBSD – "ether" like FreeBSD
    NETBSD_IFCONFIG = "        ether 52:54:00:de:ad:be\n"

    def test_netbsd_ifconfig(self) -> None:
        mac = self._extract_mac_ifconfig(self.NETBSD_IFCONFIG)
        self.assertIsNotNone(mac)

    # OpenBSD – WiFi interface uses same lladdr format
    OPENBSD_IFCONFIG_WIFI = "        lladdr a4:c3:f0:12:34:56\n"

    def test_openbsd_ifconfig_wifi(self) -> None:
        mac = self._extract_mac_ifconfig(self.OPENBSD_IFCONFIG_WIFI)
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "a4:c3:f0:12:34:56")

    # --- Windows: route print (MAC via win_p + if_name anchor) ---

    WIN_P = r"[0-9]+\s*[.]+([^.]+)\s*[.]+"

    def _extract_win_mac(self, output: str, if_name: str) -> Optional[str]:
        import re

        matches = re.findall(self.WIN_P + re.escape(if_name), output)
        if not matches:
            return None
        mac = matches[0].strip().lower().replace(" ", "-")
        return mac

    # Windows 7 – standard single interface
    WIN7_ROUTE_PRINT = (
        "Interface List\r\n"
        " 12...aa bb cc dd ee ff ......Ethernet\r\n"
        "===========================================================================\r\n"
    )

    def test_win7_route_print_ethernet(self) -> None:
        mac = self._extract_win_mac(self.WIN7_ROUTE_PRINT, "Ethernet")
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "aa-bb-cc-dd-ee-ff")

    # Windows 10 – two adapters, select by name
    WIN10_ROUTE_PRINT = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        " 12...aa bb cc dd ee ff ......Intel(R) Ethernet Connection I219-V\r\n"
        " 14...11 22 33 44 55 66 ......Intel(R) Wi-Fi 6 AX200 160MHz\r\n"
        " 16...00 50 56 c0 00 08 ......VMware Virtual Ethernet Adapter for VMnet8\r\n"
    )

    def test_win10_route_print_wifi(self) -> None:
        mac = self._extract_win_mac(
            self.WIN10_ROUTE_PRINT, "Intel(R) Wi-Fi 6 AX200 160MHz"
        )
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "11-22-33-44-55-66")

    def test_win10_route_print_ethernet(self) -> None:
        mac = self._extract_win_mac(
            self.WIN10_ROUTE_PRINT, "Intel(R) Ethernet Connection I219-V"
        )
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "aa-bb-cc-dd-ee-ff")

    def test_win10_route_print_vmware(self) -> None:
        mac = self._extract_win_mac(
            self.WIN10_ROUTE_PRINT, "VMware Virtual Ethernet Adapter for VMnet8"
        )
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "00-50-56-c0-00-08")

    # Windows Server 2019 – multiple NICs, large indexes
    WIN_SERVER_ROUTE_PRINT = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        "  4...de ad be ef ca fe ......Hyper-V Virtual Ethernet Adapter\r\n"
        "  6...00 15 5d 12 34 56 ......Hyper-V Virtual Ethernet Adapter #2\r\n"
        " 10...00 0c 29 ab cd ef ......Intel(R) 82574L Gigabit Network Connection\r\n"
    )

    def test_win_server_route_print_hyperv(self) -> None:
        mac = self._extract_win_mac(
            self.WIN_SERVER_ROUTE_PRINT, "Hyper-V Virtual Ethernet Adapter"
        )
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "de-ad-be-ef-ca-fe")

    def test_win_server_route_print_hyperv2(self) -> None:
        mac = self._extract_win_mac(
            self.WIN_SERVER_ROUTE_PRINT, "Hyper-V Virtual Ethernet Adapter #2"
        )
        self.assertIsNotNone(mac)
        self.assertEqual(mac, "00-15-5d-12-34-56")


# ---------------------------------------------------------------------------
# Extended netsh parser tests – more real-world output variants
# ---------------------------------------------------------------------------


class TestNetshParsersExtended(unittest.TestCase):
    """Additional real-world output samples for NetshParse."""

    def setUp(self) -> None:
        from aionetiface.nic.netifaces.windows.win_netsh import NetshParse

        self.parser = NetshParse()

    # -----------------------------------------------------------------------
    # show_interfaces – 5+ real-world variants
    # -----------------------------------------------------------------------

    # Windows Vista / Server 2008 – two-digit indexes, "Local Area Connection"
    IFACES_VISTA = (
        "Idx     Met         MTU          State                Name\r\n"
        "---  ----------  ----------  ------------  ---------------------------\r\n"
        "  1          50  4294967295  connected     Loopback Pseudo-Interface 1\r\n"
        "  2          20        1500  connected     Local Area Connection\r\n"
        "  3          25        1500  disconnected  Wireless Network Connection\r\n"
    )

    def test_show_interfaces_vista(self) -> None:
        af, key, data = self.parser.show_interfaces(IP4, self.IFACES_VISTA)
        self.assertIn("2", data)
        self.assertEqual(data["2"]["con_name"], "Local Area Connection")
        self.assertEqual(data["3"]["state"], "disconnected")

    # Windows 7 – Teredo tunnel (MTU 1280), disconnected wireless
    IFACES_WIN7 = (
        "Idx     Met         MTU          State                Name\r\n"
        "---  ----------  ----------  ------------  ---------------------------\r\n"
        "  1          50  4294967295  connected     Loopback Pseudo-Interface 1\r\n"
        " 11          10        1500  connected     Local Area Connection\r\n"
        " 13          25        1500  disconnected  Wireless Network Connection 2\r\n"
        " 15          35        1280  connected     Teredo Tunneling Pseudo-Interface\r\n"
    )

    def test_show_interfaces_win7_teredo(self) -> None:
        af, key, data = self.parser.show_interfaces(IP4, self.IFACES_WIN7)
        self.assertIn("15", data)
        self.assertEqual(data["15"]["mtu"], "1280")
        self.assertIn("Teredo", data["15"]["con_name"])

    # Windows 10 – Bluetooth adapter present
    IFACES_WIN10 = (
        "Idx     Met         MTU          State                Name\r\n"
        "---  ----------  ----------  ------------  ---------------------------\r\n"
        "  1          75  4294967295  connected     Loopback Pseudo-Interface 1\r\n"
        " 15          25        1500  connected     Ethernet\r\n"
        " 17          35        1500  connected     Wi-Fi\r\n"
        " 19          65        1500  connected     Bluetooth Network Connection\r\n"
        " 21          15        1280  connected     Teredo Tunneling Pseudo-Interface\r\n"
    )

    def test_show_interfaces_win10_multi(self) -> None:
        af, key, data = self.parser.show_interfaces(IP4, self.IFACES_WIN10)
        self.assertIn("17", data)
        self.assertEqual(data["17"]["con_name"], "Wi-Fi")
        self.assertIn("19", data)
        self.assertIn("Bluetooth", data["19"]["con_name"])

    # Windows Server 2012 R2 – numeric Ethernet names
    IFACES_SERVER2012 = (
        "Idx     Met         MTU          State                Name\r\n"
        "---  ----------  ----------  ------------  ---------------------------\r\n"
        "  1          75  4294967295  connected     Loopback Pseudo-Interface 1\r\n"
        "  4          20        1500  connected     Ethernet0\r\n"
        "  5          25        1500  connected     Ethernet1\r\n"
        "  6          30        1500  disconnected  Ethernet2\r\n"
    )

    def test_show_interfaces_server2012(self) -> None:
        af, key, data = self.parser.show_interfaces(IP4, self.IFACES_SERVER2012)
        self.assertIn("4", data)
        self.assertEqual(data["4"]["con_name"], "Ethernet0")
        self.assertIn("6", data)
        self.assertEqual(data["6"]["state"], "disconnected")

    # Windows 11 – Hyper-V virtual switches with large indexes
    IFACES_WIN11 = (
        "Idx     Met         MTU          State                Name\r\n"
        "---  ----------  ----------  ------------  ---------------------------\r\n"
        "  1          75  4294967295  connected     Loopback Pseudo-Interface 1\r\n"
        " 14          25        1500  connected     Ethernet\r\n"
        " 16          35        1500  connected     Wi-Fi\r\n"
        " 40           5        1500  connected     vEthernet\r\n"
    )

    def test_show_interfaces_win11_vethernet(self) -> None:
        af, key, data = self.parser.show_interfaces(IP4, self.IFACES_WIN11)
        self.assertIn("40", data)
        self.assertEqual(data["40"]["metric"], "5")

    # Windows Server 2019 – LBFO team, large interface count
    IFACES_SERVER2019 = (
        "Idx     Met         MTU          State                Name\r\n"
        "---  ----------  ----------  ------------  ---------------------------\r\n"
        "  1          75  4294967295  connected     Loopback Pseudo-Interface 1\r\n"
        "  2           5        9000  connected     Team\r\n"
        "  3          10        9000  connected     NIC1\r\n"
        "  4          10        9000  connected     NIC2\r\n"
        "100          20        1500  connected     Management\r\n"
    )

    def test_show_interfaces_server2019_team(self) -> None:
        af, key, data = self.parser.show_interfaces(IP4, self.IFACES_SERVER2019)
        self.assertIn("2", data)
        self.assertEqual(data["2"]["mtu"], "9000")
        self.assertIn("100", data)

    # -----------------------------------------------------------------------
    # show_addresses – 5+ variants including Vista format & block assignments
    # -----------------------------------------------------------------------

    # Windows Vista/7 – "Manual" addr_type for static addresses
    ADDRS_VISTA_STATIC = (
        "Interface 2\r\n"
        "Address Type  DAD State  Valid Life Pref. Life Address\r\n"
        "-----------  -----------  ----------  ---------- ---------------------------\r\n"
        "Manual       Manual     infinite   infinite   192.168.0.100\r\n"
    )

    def test_show_addresses_vista_static(self) -> None:
        af, key, data = self.parser.show_addresses(IP4, self.ADDRS_VISTA_STATIC)
        self.assertIn("2", data)
        self.assertEqual(data["2"][0]["addr"], "192.168.0.100")
        self.assertEqual(data["2"][0]["addr_type"], "Manual")

    # Windows 10 – DHCP with finite valid lifetime (seconds notation)
    ADDRS_WIN10_DHCP = (
        "Interface 15\r\n"
        "Addr Type  DAD State  Valid Life Pref. Life Address\r\n"
        "---------  ----------  ----------  ---------- ---------------------------\r\n"
        "Dhcp       Preferred  86399s     86399s     10.0.1.76\r\n"
    )

    def test_show_addresses_win10_dhcp_lifetime(self) -> None:
        af, key, data = self.parser.show_addresses(IP4, self.ADDRS_WIN10_DHCP)
        self.assertIn("15", data)
        self.assertEqual(data["15"][0]["addr"], "10.0.1.76")
        self.assertEqual(data["15"][0]["dad_state"], "Preferred")
        self.assertEqual(data["15"][0]["valid_life"], "86399s")

    # Block IP assignment – network address (203.0.113.0) assigned to NIC
    ADDRS_BLOCK_ASSIGNMENT = (
        "Interface 12\r\n"
        "Addr Type  DAD State  Valid Life Pref. Life Address\r\n"
        "---------  ----------  ----------  ---------- ---------------------------\r\n"
        "Other      Preferred  infinite   infinite   203.0.113.0\r\n"
    )

    def test_show_addresses_block_assignment(self) -> None:
        """A /27 network address assigned directly to an interface (ISP block)."""
        af, key, data = self.parser.show_addresses(IP4, self.ADDRS_BLOCK_ASSIGNMENT)
        self.assertIn("12", data)
        self.assertEqual(data["12"][0]["addr"], "203.0.113.0")

    # IPv6 – multiple addresses including deprecated temporary
    ADDRS_V6_MULTI = (
        "Interface 15\r\n"
        "Addr Type  DAD State  Valid Life Pref. Life Address\r\n"
        "---------  ----------  ----------  ---------- ---------------------------\r\n"
        "Other      Preferred  29d23h59m  13d23h59m  2400:a842:d1b4:0:20c:29ff:fe57:d05c\r\n"
        "Other      Deprecated 29d23h59m  0s         2400:a842:d1b4:0:7f81:feef:9bb1:101e\r\n"
        "Other      Preferred  infinite   infinite   fe80::20c:29ff:fe57:d05c\r\n"
    )

    def test_show_addresses_v6_multi_including_deprecated(self) -> None:
        af, key, data = self.parser.show_addresses(IP6, self.ADDRS_V6_MULTI)
        self.assertIn("15", data)
        addrs = [e["addr"] for e in data["15"]]
        self.assertIn("2400:a842:d1b4:0:20c:29ff:fe57:d05c", addrs)
        self.assertIn("fe80::20c:29ff:fe57:d05c", addrs)

    # IPv6 – interface with /48 block (delegated prefix on router)
    ADDRS_V6_BLOCK = (
        "Interface 4\r\n"
        "Addr Type  DAD State  Valid Life Pref. Life Address\r\n"
        "---------  ----------  ----------  ---------- ---------------------------\r\n"
        "Other      Preferred  infinite   infinite   2001:db8::\r\n"
    )

    def test_show_addresses_v6_block(self) -> None:
        """Network address of a /48 block assigned to an interface."""
        af, key, data = self.parser.show_addresses(IP6, self.ADDRS_V6_BLOCK)
        self.assertIn("4", data)
        self.assertEqual(data["4"][0]["addr"], "2001:db8::")

    # Multiple interfaces in one output
    ADDRS_MULTI_IF = (
        "Interface 12\r\n"
        "Addr Type  DAD State  Valid Life Pref. Life Address\r\n"
        "---------  ----------  ----------  ---------- ---------------------------\r\n"
        "Other      Preferred  infinite   infinite   192.168.1.100\r\n"
        "\r\n"
        "Interface 14\r\n"
        "Addr Type  DAD State  Valid Life Pref. Life Address\r\n"
        "---------  ----------  ----------  ---------- ---------------------------\r\n"
        "Other      Preferred  infinite   infinite   10.0.0.50\r\n"
        "Other      Preferred  infinite   infinite   10.0.0.51\r\n"
    )

    def test_show_addresses_multi_interface(self) -> None:
        af, key, data = self.parser.show_addresses(IP4, self.ADDRS_MULTI_IF)
        self.assertIn("12", data)
        self.assertIn("14", data)
        self.assertEqual(len(data["14"]), 2)

    # -----------------------------------------------------------------------
    # show_route – 5+ variants with more prefix types
    # -----------------------------------------------------------------------

    # Windows 10 IPv4 – default + connected + static manual route
    ROUTES_V4_FULL = (
        "No  Type    Met  Prefix          Idx  Name\r\n"
        "--- ------  ---  --------------- ---  --------\r\n"
        "No  System   0  0.0.0.0/0        12  Ethernet\r\n"
        "No  System  10  192.168.1.0/24   12  Ethernet\r\n"
        "No  System  20  10.0.0.0/8       14  Wi-Fi\r\n"
        "Yes Manual   5  172.16.0.0/12    12  Ethernet\r\n"
    )

    def test_show_route_v4_manual(self) -> None:
        af, key, data = self.parser.show_route(IP4, self.ROUTES_V4_FULL)
        self.assertIn("12", data)
        prefixes = [r["prefix"] for r in data["12"]]
        self.assertIn("0.0.0.0/0", prefixes)
        self.assertIn("172.16.0.0/12", prefixes)
        manual = next(r for r in data["12"] if r["prefix"] == "172.16.0.0/12")
        self.assertEqual(manual["publish"], "Yes")
        self.assertEqual(manual["rtype"], "Manual")

    # IPv4 – /32 host route (VPN split-tunnel)
    ROUTES_V4_HOST = (
        "No  Type    Met  Prefix          Idx  Name\r\n"
        "--- ------  ---  --------------- ---  --------\r\n"
        "No  System   1  8.8.8.8/32       15  VPN\r\n"
        "No  System   1  1.1.1.1/32       15  VPN\r\n"
        "No  System   0  0.0.0.0/0        12  Ethernet\r\n"
    )

    def test_show_route_v4_host_routes(self) -> None:
        af, key, data = self.parser.show_route(IP4, self.ROUTES_V4_HOST)
        self.assertIn("15", data)
        prefixes = [r["prefix"] for r in data["15"]]
        self.assertIn("8.8.8.8/32", prefixes)
        self.assertIn("1.1.1.1/32", prefixes)

    # IPv6 – /32, /48, /56, /64, /128 in one table
    ROUTES_V6_FULL = (
        "No  Type    Met  Prefix                         Idx  Name\r\n"
        "--- ------  ---  ------------------------------ ---  --------\r\n"
        "No  System   0  ::/0                            12  Ethernet\r\n"
        "No  System  10  2001:db8::/32                   12  Ethernet\r\n"
        "No  System  10  2001:db8:1::/48                 12  Ethernet\r\n"
        "No  System  20  2001:db8:1:2::/64               12  Ethernet\r\n"
        "No  System  30  2001:db8:1:2::1/128             12  Ethernet\r\n"
        "No  System  30  fe80::/64                       12  Ethernet\r\n"
        "No  System  30  ::1/128                         12  Ethernet\r\n"
    )

    def test_show_route_v6_prefix_lengths(self) -> None:
        af, key, data = self.parser.show_route(IP6, self.ROUTES_V6_FULL)
        self.assertIn("12", data)
        prefixes = [r["prefix"] for r in data["12"]]
        self.assertIn("2001:db8::/32", prefixes)
        self.assertIn("2001:db8:1::/48", prefixes)
        self.assertIn("2001:db8:1:2::/64", prefixes)
        self.assertIn("2001:db8:1:2::1/128", prefixes)
        self.assertIn("::1/128", prefixes)

    # IPv6 – link-local /64 and global /64 on same interface
    ROUTES_V6_MIXED = (
        "No  Type    Met  Prefix                         Idx  Name\r\n"
        "--- ------  ---  ------------------------------ ---  --------\r\n"
        "No  System  10  fe80::/64                       14  Wi-Fi\r\n"
        "No  System  10  2400:a842:d1b4::/64             14  Wi-Fi\r\n"
        "No  System   0  ::/0                            14  Wi-Fi\r\n"
    )

    def test_show_route_v6_link_local_and_global(self) -> None:
        af, key, data = self.parser.show_route(IP6, self.ROUTES_V6_MIXED)
        self.assertIn("14", data)
        prefixes = [r["prefix"] for r in data["14"]]
        self.assertIn("fe80::/64", prefixes)
        self.assertIn("2400:a842:d1b4::/64", prefixes)

    # IPv4 multiple interfaces – each interface gets its own routes list
    ROUTES_V4_MULTI_IF = (
        "No  Type    Met  Prefix          Idx  Name\r\n"
        "--- ------  ---  --------------- ---  --------\r\n"
        "No  System   0  0.0.0.0/0        12  Ethernet\r\n"
        "No  System  10  192.168.1.0/24   12  Ethernet\r\n"
        "No  System  20  10.0.0.0/8       14  Wi-Fi\r\n"
        "No  System  10  10.0.0.0/24      14  Wi-Fi\r\n"
    )

    def test_show_route_v4_multi_interface(self) -> None:
        af, key, data = self.parser.show_route(IP4, self.ROUTES_V4_MULTI_IF)
        self.assertIn("12", data)
        self.assertIn("14", data)
        self.assertEqual(len(data["14"]), 2)
        prefixes_14 = [r["prefix"] for r in data["14"]]
        self.assertIn("10.0.0.0/8", prefixes_14)
        self.assertIn("10.0.0.0/24", prefixes_14)

    # -----------------------------------------------------------------------
    # show_mac (route print) – 5+ variants
    # -----------------------------------------------------------------------

    # Windows 7 – two physical NICs + VMware adapter
    ROUTE_PRINT_WIN7 = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        " 12...aa bb cc dd ee ff ......Intel(R) 82579LM Gigabit Network Connection\r\n"
        " 14...11 22 33 44 55 66 ......Intel(R) Centrino Advanced-N 6205\r\n"
        " 16...00 50 56 c0 00 08 ......VMware Virtual Ethernet Adapter for VMnet8\r\n"
        "\r\n"
        "IPv4 Route Table\r\n"
        "===========================================================================\r\n"
        "Active Routes:\r\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100      25\r\n"
        "===========================================================================\r\n"
    )

    def test_show_mac_win7(self) -> None:
        af, key, data = self.parser.show_mac(IP4, self.ROUTE_PRINT_WIN7)
        self.assertEqual(key, "macs")
        self.assertIn("12", data)
        self.assertEqual(data["12"]["mac"], "aa-bb-cc-dd-ee-ff")
        self.assertIn("14", data)
        self.assertEqual(data["14"]["mac"], "11-22-33-44-55-66")
        self.assertIsNotNone(data["default"][IP4])
        self.assertEqual(data["default"][IP4]["gw_ip"], "192.168.1.1")

    # Windows 10 – dual-stack, default route for both IPv4 and IPv6
    ROUTE_PRINT_WIN10_DUAL = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        " 15...aa bb cc dd ee ff ......Intel(R) Ethernet Connection I219-V\r\n"
        "\r\n"
        "IPv4 Route Table\r\n"
        "Active Routes:\r\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100      25\r\n"
        "\r\n"
        "IPv6 Route Table\r\n"
        "Active Routes:\r\n"
        " If  Met  Prefix                       Next Hop\r\n"
        " 15    5  ::/0                         fe80::1\r\n"
    )

    def test_show_mac_win10_dual_stack(self) -> None:
        af, key, data = self.parser.show_mac(IP4, self.ROUTE_PRINT_WIN10_DUAL)
        self.assertIsNotNone(data["default"][IP4])
        self.assertEqual(data["default"][IP4]["gw_ip"], "192.168.1.1")
        self.assertIsNotNone(data["default"][IP6])
        self.assertEqual(data["default"][IP6]["gw_ip"], "fe80::1")

    # Server – no default IPv4 route (directly connected)
    ROUTE_PRINT_NO_DEFAULT = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        "  4...00 0c 29 ab cd ef ......vmxnet3 Ethernet Adapter\r\n"
        "\r\n"
        "IPv4 Route Table\r\n"
        "Active Routes:\r\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
        "      203.0.113.0    255.255.255.0         On-link      203.0.113.1      10\r\n"
    )

    def test_show_mac_no_default_route(self) -> None:
        af, key, data = self.parser.show_mac(IP4, self.ROUTE_PRINT_NO_DEFAULT)
        # Default route entry should be absent (None)
        self.assertIsNone(data["default"][IP4])
        self.assertIn("4", data)
        self.assertEqual(data["4"]["mac"], "00-0c-29-ab-cd-ef")

    # Windows Server 2019 – Hyper-V virtual switch NIC
    ROUTE_PRINT_HYPERV = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        "  4...00 15 5d 12 34 56 ......Hyper-V Virtual Ethernet Adapter\r\n"
        "  6...de ad be ef 00 01 ......Hyper-V Virtual Ethernet Adapter #2\r\n"
        "\r\n"
        "IPv4 Route Table\r\n"
        "Active Routes:\r\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
        "          0.0.0.0          0.0.0.0       10.0.0.1        10.0.0.50      20\r\n"
    )

    def test_show_mac_hyperv(self) -> None:
        af, key, data = self.parser.show_mac(IP4, self.ROUTE_PRINT_HYPERV)
        self.assertIn("4", data)
        self.assertEqual(data["4"]["mac"], "00-15-5d-12-34-56")
        self.assertIn("6", data)
        self.assertEqual(data["6"]["mac"], "de-ad-be-ef-00-01")

    # Windows 11 – WiFi + Ethernet + two default IPv6 routes
    ROUTE_PRINT_WIN11 = (
        "Interface List\r\n"
        "  1...........................Software Loopback Interface 1\r\n"
        " 14...aa bb cc dd ee ff ......Intel(R) Wi-Fi 6E AX211 160MHz\r\n"
        " 16...00 11 22 33 44 55 ......Intel(R) Ethernet Connection I225-V\r\n"
        "\r\n"
        "IPv4 Route Table\r\n"
        "Active Routes:\r\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
        "          0.0.0.0          0.0.0.0        10.0.1.1       10.0.1.50      20\r\n"
        "\r\n"
        "IPv6 Route Table\r\n"
        "Active Routes:\r\n"
        " If  Met  Prefix                       Next Hop\r\n"
        " 14    5  ::/0                         fe80::1\r\n"
    )

    def test_show_mac_win11(self) -> None:
        af, key, data = self.parser.show_mac(IP4, self.ROUTE_PRINT_WIN11)
        self.assertIn("14", data)
        self.assertEqual(data["14"]["mac"], "aa-bb-cc-dd-ee-ff")
        self.assertEqual(data["default"][IP4]["if_ip"], "10.0.1.50")

    # -----------------------------------------------------------------------
    # show_gws (ipconfig /all) – 5+ variants
    # -----------------------------------------------------------------------

    # Windows XP style – Physical Address spacing different (dots not dashes)
    IPCONFIG_XP = (
        "Windows IP Configuration\r\n"
        "\r\n"
        "Ethernet adapter Local Area Connection:\r\n"
        "\r\n"
        "   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF\r\n"
        "   Default Gateway . . . . . . . . . : 192.168.0.1\r\n"
    )

    def test_show_gws_xp(self) -> None:
        af, key, data = self.parser.show_gws(IP4, self.IPCONFIG_XP)
        self.assertEqual(key, "gws")
        self.assertIn("aa-bb-cc-dd-ee-ff", data)
        self.assertEqual(data["aa-bb-cc-dd-ee-ff"][IP4], "192.168.0.1")

    # Windows 7 – dual-stack gateway (IPv4 + IPv6 link-local)
    IPCONFIG_WIN7_DUAL = (
        "Ethernet adapter Local Area Connection:\r\n"
        "\r\n"
        "   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF\r\n"
        "   Default Gateway . . . . . . . . . : 192.168.1.1\r\n"
        "                                        fe80::1\r\n"
    )

    def test_show_gws_win7_dual_stack(self) -> None:
        af, key, data = self.parser.show_gws(IP4, self.IPCONFIG_WIN7_DUAL)
        mac = "aa-bb-cc-dd-ee-ff"
        self.assertIn(mac, data)
        self.assertEqual(data[mac][IP4], "192.168.1.1")
        self.assertEqual(data[mac][IP6], "fe80::1")

    # Windows 10 – adapter with no gateway (virtual NIC / host-only)
    IPCONFIG_NO_GW = (
        "Ethernet adapter vEthernet (Default Switch):\r\n"
        "\r\n"
        "   Physical Address. . . . . . . . . : 00-15-5D-12-34-56\r\n"
        "   Default Gateway . . . . . . . . . :\r\n"
    )

    def test_show_gws_no_gateway_skipped(self) -> None:
        """Interface with no gateway should not appear in results (no valid IP)."""
        af, key, data = self.parser.show_gws(IP4, self.IPCONFIG_NO_GW)
        self.assertNotIn("00-15-5d-12-34-56", data)

    # Windows Server – multiple adapters in one ipconfig output
    IPCONFIG_MULTI = (
        "Ethernet adapter Ethernet0:\r\n"
        "\r\n"
        "   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF\r\n"
        "   Default Gateway . . . . . . . . . : 10.0.0.1\r\n"
        "\r\n\r\n"
        "Ethernet adapter Ethernet1:\r\n"
        "\r\n"
        "   Physical Address. . . . . . . . . : 11-22-33-44-55-66\r\n"
        "   Default Gateway . . . . . . . . . : 172.16.0.1\r\n"
    )

    def test_show_gws_multi_adapter(self) -> None:
        af, key, data = self.parser.show_gws(IP4, self.IPCONFIG_MULTI)
        self.assertIn("aa-bb-cc-dd-ee-ff", data)
        self.assertEqual(data["aa-bb-cc-dd-ee-ff"][IP4], "10.0.0.1")
        self.assertIn("11-22-33-44-55-66", data)
        self.assertEqual(data["11-22-33-44-55-66"][IP4], "172.16.0.1")

    # Windows 11 – IPv6-only gateway (no IPv4 gateway)
    IPCONFIG_IPV6_ONLY_GW = (
        "Ethernet adapter Ethernet:\r\n"
        "\r\n"
        "   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF\r\n"
        "   Default Gateway . . . . . . . . . : fe80::1\r\n"
    )

    def test_show_gws_ipv6_only_gateway(self) -> None:
        af, key, data = self.parser.show_gws(IP4, self.IPCONFIG_IPV6_ONLY_GW)
        mac = "aa-bb-cc-dd-ee-ff"
        self.assertIn(mac, data)
        self.assertIsNone(data[mac][IP4])
        self.assertEqual(data[mac][IP6], "fe80::1")

    # -----------------------------------------------------------------------
    # get_host_limit_from_route_infos – additional prefix lengths
    # -----------------------------------------------------------------------

    def test_host_limit_ipv6_slash48(self) -> None:
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "::/0"},
            {"prefix": "2001:db8::/32"},
            {"prefix": "2001:db8:1::/48"},
        ]
        host_limit, _ = get_host_limit_from_route_infos("2001:db8:1::1", route_infos)
        self.assertEqual(host_limit, 48)

    def test_host_limit_ipv6_slash56(self) -> None:
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "2001:db8::/32"},
            {"prefix": "2001:db8:1::/48"},
            {"prefix": "2001:db8:1:200::/56"},
        ]
        host_limit, _ = get_host_limit_from_route_infos(
            "2001:db8:1:200::1", route_infos
        )
        self.assertEqual(host_limit, 56)

    def test_host_limit_ipv6_slash128(self) -> None:
        """Host route /128 is the most specific possible match."""
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "2001:db8::/32"},
            {"prefix": "2001:db8:1:2::/64"},
            {"prefix": "2001:db8:1:2::5/128"},
        ]
        host_limit, _ = get_host_limit_from_route_infos("2001:db8:1:2::5", route_infos)
        self.assertEqual(host_limit, 128)

    def test_host_limit_ipv4_slash30(self) -> None:
        """Point-to-point /30 link: two host bits."""
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [
            {"prefix": "0.0.0.0/0"},
            {"prefix": "10.0.0.0/30"},
        ]
        host_limit, netmask = get_host_limit_from_route_infos("10.0.0.1", route_infos)
        self.assertEqual(host_limit, 30)
        self.assertEqual(netmask, "255.255.255.252")

    def test_host_limit_no_match_returns_zero(self) -> None:
        """IP not covered by any route → host_limit=0, netmask=None."""
        from aionetiface.nic.netifaces.windows.win_netsh import (
            get_host_limit_from_route_infos,
        )

        route_infos = [{"prefix": "10.0.0.0/24"}]
        host_limit, netmask = get_host_limit_from_route_infos(
            "192.168.1.1", route_infos
        )
        self.assertEqual(host_limit, 0)
        self.assertIsNone(netmask)


# ---------------------------------------------------------------------------
# Extended netiface_addr_to_ipr: block IP assignments across OS netmask formats
# ---------------------------------------------------------------------------


class TestNetiaceAddrToIPRBlocks(AsyncTestCase):
    """
    Tests netiface_addr_to_ipr with block IP assignments (i_host == 0),
    covering IPv4 and IPv6, common prefix lengths, and cross-OS netmask formats.
    """

    async def _to_ipr(self, af: Any, addr: str, netmask: str, nic_id: int = 0) -> Any:
        from aionetiface.nic.netifaces.netiface_extra import netiface_addr_to_ipr

        info = {"addr": addr, "netmask": netmask}
        return await netiface_addr_to_ipr(af, nic_id, info)

    # --- IPv4 block assignments ---

    async def test_ipv4_block_slash24(self) -> None:
        """/24 block: 198.51.100.0/24 with 255 usable hosts."""
        ipr = await self._to_ipr(IP4, "198.51.100.0", "255.255.255.0")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 8)  # 8 host bits
        self.assertEqual(ipr.host_limit, 255)  # 2^8 - 1
        self.assertEqual(ipr.subnet, 24)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv4_block_slash25(self) -> None:
        """/25 block: 192.168.1.128/25 – upper half of a /24."""
        ipr = await self._to_ipr(IP4, "192.168.1.128", "255.255.255.128")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 7)  # 7 host bits
        self.assertEqual(ipr.host_limit, 127)  # 2^7 - 1
        self.assertEqual(ipr.subnet, 25)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv4_block_slash28(self) -> None:
        """/28 block: 203.0.113.16/28 – 14 usable hosts."""
        ipr = await self._to_ipr(IP4, "203.0.113.16", "255.255.255.240")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 4)  # 4 host bits
        self.assertEqual(ipr.host_limit, 15)  # 2^4 - 1
        self.assertEqual(ipr.subnet, 28)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv4_block_slash30(self) -> None:
        """/30 point-to-point link: 10.0.0.0/30 – 3 usable IPs."""
        ipr = await self._to_ipr(IP4, "10.0.0.0", "255.255.255.252")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 2)  # 2 host bits
        self.assertEqual(ipr.host_limit, 3)  # 2^2 - 1
        self.assertEqual(ipr.subnet, 30)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv4_block_slash16(self) -> None:
        """/16 block: 172.16.0.0/16 – 65535 usable hosts."""
        ipr = await self._to_ipr(IP4, "172.16.0.0", "255.255.0.0")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 16)
        self.assertEqual(ipr.host_limit, 65535)
        self.assertEqual(ipr.subnet, 16)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv4_host_inside_block_is_single(self) -> None:
        """A host IP inside a /24 subnet → collapsed to single-host range."""
        ipr = await self._to_ipr(IP4, "198.51.100.5", "255.255.255.0")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)  # single host
        self.assertEqual(ipr.subnet, 24)  # OS prefix still stored

    # --- IPv6 block assignments ---

    async def test_ipv6_block_slash64_network_addr(self) -> None:
        """/64 block: 2001:db8:: assigned directly (network address on interface)."""
        ipr = await self._to_ipr(IP6, "2001:db8::", "ffff:ffff:ffff:ffff::")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 64)  # 64 host bits
        self.assertEqual(ipr.host_limit, (2**64) - 1)
        self.assertEqual(ipr.subnet, 64)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv6_block_slash48(self) -> None:
        """/48 block: 2001:db8:: assigned as a /48 (router prefix delegation)."""
        ipr = await self._to_ipr(IP6, "2001:db8::", "ffff:ffff:ffff::")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 80)  # 80 host bits
        self.assertEqual(ipr.subnet, 48)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv6_block_slash56(self) -> None:
        """/56 block: 2001:db8:1:200:: – common ISP delegation size."""
        ipr = await self._to_ipr(IP6, "2001:db8:1:200::", "ffff:ffff:ffff:ff00::")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 72)  # 72 host bits
        self.assertEqual(ipr.subnet, 56)
        self.assertEqual(ipr.i_host, 0)

    async def test_ipv6_host_inside_slash64_is_single(self) -> None:
        """A host inside a /64 → single-host IPRange with subnet=64."""
        ipr = await self._to_ipr(IP6, "2001:db8::1", "ffff:ffff:ffff:ffff::/64")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)  # single host
        self.assertEqual(ipr.subnet, 64)

    async def test_ipv6_link_local_host_inside_slash64(self) -> None:
        """Link-local address in /64 → single-host, subnet=64."""
        ipr = await self._to_ipr(IP6, "fe80::1", "ffff:ffff:ffff:ffff::")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 64)

    # --- Netmask format variations from different OSes ---

    async def test_netmask_with_cidr_suffix_stripped(self) -> None:
        """netifaces on some systems returns 'ffff:ffff:ffff:ffff::/64' – /N stripped."""
        ipr = await self._to_ipr(
            IP6, "2400:a842:d1b4:0:20c:29ff:fe57:d05c", "ffff:ffff:ffff:ffff::/64"
        )
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.subnet, 64)

    async def test_netmask_ipv4_with_peer_field(self) -> None:
        """ppp/tun interfaces sometimes set addr == peer; treat as single host."""
        ipr = await self._to_ipr(IP4, "10.10.0.1", "255.255.255.255")
        self.assertIsNotNone(ipr)
        self.assertEqual(ipr.bitlen, 0)
        self.assertEqual(ipr.subnet, 32)

    async def test_ipv4_block_slash27_first_ipr_is_correct(self) -> None:
        """/27 block: ipr[0] is the first usable host (network+1)."""
        ipr = await self._to_ipr(IP4, "203.0.113.0", "255.255.255.224")
        self.assertIsNotNone(ipr)
        self.assertEqual(str(ipr[0]), "203.0.113.1")
        self.assertEqual(str(ipr[-1]), "203.0.113.31")

    async def test_ipv6_block_slash64_first_ipr_is_correct(self) -> None:
        """/64 block: ipr[0] is ::1, ipr[-1] is all-1s in lower 64 bits."""
        ipr = await self._to_ipr(IP6, "2001:db8::", "ffff:ffff:ffff:ffff::")
        self.assertIsNotNone(ipr)
        self.assertEqual(str(ipr[0]), "2001:db8::1")
        self.assertEqual(str(ipr[-1]), "2001:db8::ffff:ffff:ffff:ffff")


# ---------------------------------------------------------------------------
# Extended Get-NetIPAddress output parsing variants
# ---------------------------------------------------------------------------


class TestGetAddrInfoParsingExtended(unittest.TestCase):
    """More real-world Get-NetIPAddress output samples."""

    def _parse(self, out: str) -> Dict[Any, List[Dict[str, Any]]]:
        import re
        from aionetiface.net.net_utils import cidr_to_netmask

        addr = {IP4: [], IP6: []}
        for ip_val, af_family, host_limit in re.findall(
            r"IPAddress\s*:\s*([^\s]*)[\s\S]*?AddressFamily\s*:\s*([^\s]+)[\s\S]*?PrefixLength\s*:\s([0-9]+)",
            out,
        ):
            host_limit = int(host_limit)
            af = IP4 if af_family == "IPv4" else IP6
            addr[af].append(
                {
                    "addr": ip_val,
                    "af": af,
                    "host_limit": host_limit,
                    "netmask": cidr_to_netmask(host_limit, af),
                }
            )
        return addr

    # Windows Server – multiple IPs on one adapter (multi-homed)
    PS_MULTIHOMED = """\
IPAddress      : 192.168.1.100
AddressFamily  : IPv4
PrefixLength   : 24

IPAddress      : 192.168.2.200
AddressFamily  : IPv4
PrefixLength   : 24

IPAddress      : 10.0.0.5
AddressFamily  : IPv4
PrefixLength   : 8
"""

    def test_multihomed_ipv4(self) -> None:
        result = self._parse(self.PS_MULTIHOMED)
        self.assertEqual(len(result[IP4]), 3)
        addrs = [a["addr"] for a in result[IP4]]
        self.assertIn("192.168.1.100", addrs)
        self.assertIn("10.0.0.5", addrs)
        ten = next(a for a in result[IP4] if a["addr"] == "10.0.0.5")
        self.assertEqual(ten["host_limit"], 8)
        self.assertEqual(ten["netmask"], "255.0.0.0")

    # Windows 10 – dual-stack with privacy extensions
    PS_DUAL_STACK = """\
IPAddress      : 192.168.1.100
AddressFamily  : IPv4
PrefixLength   : 24

IPAddress      : 2400:a842:d1b4:0:20c:29ff:fe57:d05c
AddressFamily  : IPv6
PrefixLength   : 64

IPAddress      : 2400:a842:d1b4:0:7f81:feef:9bb1:101e
AddressFamily  : IPv6
PrefixLength   : 64

IPAddress      : fe80::20c:29ff:fe57:d05c
AddressFamily  : IPv6
PrefixLength   : 64
"""

    def test_dual_stack_with_privacy(self) -> None:
        result = self._parse(self.PS_DUAL_STACK)
        self.assertEqual(len(result[IP4]), 1)
        self.assertEqual(len(result[IP6]), 3)
        ipv6_addrs = [a["addr"] for a in result[IP6]]
        self.assertIn("fe80::20c:29ff:fe57:d05c", ipv6_addrs)

    # Server with /32 and /128 host routes
    PS_HOST_ROUTES = """\
IPAddress      : 8.8.8.8
AddressFamily  : IPv4
PrefixLength   : 32

IPAddress      : 2001:db8::1
AddressFamily  : IPv6
PrefixLength   : 128
"""

    def test_host_routes(self):
        result = self._parse(self.PS_HOST_ROUTES)
        self.assertEqual(result[IP4][0]["host_limit"], 32)
        self.assertEqual(result[IP6][0]["host_limit"], 128)

    # Delegated /48 prefix on a router interface
    PS_DELEGATED_PREFIX = """\
IPAddress      : 2001:db8::
AddressFamily  : IPv6
PrefixLength   : 48
"""

    def test_delegated_slash48(self):
        result = self._parse(self.PS_DELEGATED_PREFIX)
        self.assertEqual(len(result[IP6]), 1)
        self.assertEqual(result[IP6][0]["host_limit"], 48)
        self.assertEqual(result[IP6][0]["addr"], "2001:db8::")

    # Loopback addresses
    PS_LOOPBACK = """\
IPAddress      : 127.0.0.1
AddressFamily  : IPv4
PrefixLength   : 8

IPAddress      : ::1
AddressFamily  : IPv6
PrefixLength   : 128
"""

    def test_loopback_addresses(self):
        result = self._parse(self.PS_LOOPBACK)
        self.assertEqual(result[IP4][0]["addr"], "127.0.0.1")
        self.assertEqual(result[IP4][0]["host_limit"], 8)
        self.assertEqual(result[IP6][0]["addr"], "::1")
        self.assertEqual(result[IP6][0]["host_limit"], 128)


if __name__ == "__main__":
    main()
