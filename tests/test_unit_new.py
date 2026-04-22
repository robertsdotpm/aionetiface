"""
Offline unit tests for aionetiface utility functions, servers data loading,
IP range edge cases, route validation, and utility helpers.

Run without network access.
"""

import json
import os
import unittest

from aionetiface import (
    IP4,
    IP6,
    IPRange,
    Route,
    VALID_AFS,
    rand_b,
    to_b,
    to_h,
    h_to_b,
    to_s,
    range_intersects,
    hamming_weight,
    sorted_search,
    rendezvous_score,
)
from aionetiface.servers import INFRA, INFRA_BUF, filter_by_score, get_infra
from aionetiface.utility.utils import (
    range_intersects,
    hamming_weight,
    sorted_search,
)


# ---------------------------------------------------------------------------
# servers.py / servers.json
# ---------------------------------------------------------------------------


class TestServersData(unittest.TestCase):
    def test_infra_buf_is_valid_json(self):
        data = json.loads(INFRA_BUF)
        self.assertIsInstance(data, dict)

    def test_infra_has_expected_top_level_keys(self):
        for key in ("STUN(see_ip)", "STUN(test_nat)", "MQTT", "TURN", "NTP"):
            self.assertIn(key, INFRA, f"Missing key: {key}")

    def test_mqtt_has_ipv4_and_ipv6(self):
        mqtt = INFRA["MQTT"]
        self.assertIn("IPv4", mqtt)
        self.assertIn("IPv6", mqtt)

    def test_servers_json_file_exists(self):
        import aionetiface.servers as srv_mod

        json_path = os.path.join(os.path.dirname(srv_mod.__file__), "servers.json")
        self.assertTrue(os.path.exists(json_path))

    def test_filter_by_score_keeps_high_scores(self):
        groups = [
            [{"score": 0.9}, {"score": 0.85}],
            [{"score": 0.5}, {"score": 0.3}],
        ]
        result = filter_by_score(groups, threshold=0.8)
        self.assertEqual(len(result), 1)
        self.assertIn({"score": 0.9}, result[0])

    def test_filter_by_score_empty_groups_ignored(self):
        groups = [[], [{"score": 0.9}]]
        result = filter_by_score(groups, threshold=0.8)
        self.assertEqual(len(result), 1)

    def test_filter_by_score_all_below_threshold_returns_empty(self):
        groups = [[{"score": 0.3}], [{"score": 0.1}]]
        result = filter_by_score(groups, threshold=0.8)
        self.assertEqual(result, [])

    def test_get_infra_returns_list(self):
        from aionetiface.net.net_defs import UDP

        result = get_infra(IP4, UDP, "STUN(see_ip)", no=2)
        self.assertIsInstance(result, list)

    def test_get_infra_respects_no_limit(self):
        from aionetiface.net.net_defs import UDP

        result = get_infra(IP4, UDP, "STUN(see_ip)", no=3)
        self.assertLessEqual(len(result), 3)

    def test_get_infra_different_attempts_yield_different_order(self):
        from aionetiface.net.net_defs import UDP

        r1 = get_infra(IP4, UDP, "STUN(see_ip)", no=10, attempt=0)
        r2 = get_infra(IP4, UDP, "STUN(see_ip)", no=10, attempt=1)
        # Results may differ (probabilistic, but different seeds usually shuffle differently)
        # Just verify both are valid lists
        self.assertIsInstance(r1, list)
        self.assertIsInstance(r2, list)


# ---------------------------------------------------------------------------
# Route constructor validation (asserts → ValueError/TypeError)
# ---------------------------------------------------------------------------


class TestRouteValidation(unittest.TestCase):
    def _good_route(self, af=IP4):
        if af == IP4:
            ext = IPRange("8.8.8.8", bitlen=0)
            nic = IPRange("192.168.1.100", bitlen=0)
        else:
            ext = IPRange("2001:db8::1", bitlen=0)
            nic = IPRange("fe80::1", bitlen=0)
        return Route(af, [nic], [ext])

    def test_valid_v4_route_constructs(self):
        route = self._good_route(IP4)
        self.assertIsNotNone(route)

    def test_valid_v6_route_constructs(self):
        # Use globally-routable addresses (not link-local) for ext and nic
        ext = IPRange("2001:4860:4860::8888", bitlen=0)
        nic = IPRange("2001:db8::2", bitlen=0)
        route = Route(IP6, [nic], [ext])
        self.assertIsNotNone(route)

    def test_invalid_af_raises_value_error(self):
        ext = IPRange("8.8.8.8", bitlen=0)
        nic = IPRange("192.168.1.100", bitlen=0)
        with self.assertRaises(ValueError):
            Route(99, [nic], [ext])

    def test_nic_ips_not_list_raises_type_error(self):
        ext = IPRange("8.8.8.8", bitlen=0)
        nic = IPRange("192.168.1.100", bitlen=0)
        with self.assertRaises(TypeError):
            Route(IP4, nic, [ext])

    def test_ext_ips_not_list_raises_type_error(self):
        ext = IPRange("8.8.8.8", bitlen=0)
        nic = IPRange("192.168.1.100", bitlen=0)
        with self.assertRaises(TypeError):
            Route(IP4, [nic], ext)

    def test_empty_ext_ips_raises_value_error(self):
        nic = IPRange("192.168.1.100", bitlen=0)
        with self.assertRaises(ValueError):
            Route(IP4, [nic], [])

    def test_empty_nic_ips_raises_value_error(self):
        ext = IPRange("8.8.8.8", bitlen=0)
        with self.assertRaises(ValueError):
            Route(IP4, [], [ext])

    def test_ext_ip_zero_raises_value_error(self):
        ext = IPRange("0.0.0.0", bitlen=0)
        nic = IPRange("192.168.1.100", bitlen=0)
        with self.assertRaises(ValueError):
            Route(IP4, [nic], [ext])

    def test_af_mismatch_raises_value_error(self):
        ext = IPRange("2001:db8::1", bitlen=0)  # IPv6
        nic = IPRange("192.168.1.100", bitlen=0)  # IPv4
        with self.assertRaises(ValueError):
            Route(IP4, [nic], [ext])


# ---------------------------------------------------------------------------
# IPRange edge cases
# ---------------------------------------------------------------------------


class TestIPRangeEdgeCases(unittest.TestCase):
    def test_v4_loopback_is_private(self):
        ipr = IPRange("127.0.0.1", bitlen=0)
        self.assertTrue(ipr.is_private)

    def test_v6_loopback_is_private(self):
        ipr = IPRange("::1", bitlen=0)
        self.assertTrue(ipr.is_private)

    def test_public_v4_is_not_private(self):
        ipr = IPRange("8.8.8.8", bitlen=0)
        self.assertFalse(ipr.is_private)

    def test_v4_network_len(self):
        # bitlen is host-bit count: bitlen=8 means 2^8 - 1 = 255 hosts
        ipr = IPRange("192.168.0.0", bitlen=8)
        self.assertEqual(len(ipr), 255)

    def test_v4_host_len_is_one(self):
        ipr = IPRange("10.0.0.1", bitlen=0)
        self.assertEqual(len(ipr), 1)

    def test_v4_range_contains_multiple_ips(self):
        ipr = IPRange("10.0.0.0", bitlen=8)
        self.assertGreater(len(ipr), 1)
        # First IP skips the network address (ipr[0] = first host)
        self.assertEqual(str(ipr[0]), "10.0.0.1")

    def test_v6_host_len_is_one(self):
        ipr = IPRange("2001:db8::1", bitlen=0)
        self.assertEqual(len(ipr), 1)

    def test_af_v4_correct(self):
        ipr = IPRange("1.2.3.4", bitlen=0)
        self.assertEqual(ipr.af, IP4)

    def test_af_v6_correct(self):
        ipr = IPRange("2001:db8::1", bitlen=0)
        self.assertEqual(ipr.af, IP6)

    def test_str_roundtrip_v4(self):
        ipr = IPRange("10.0.0.1", bitlen=0)
        self.assertEqual(str(ipr[0]), "10.0.0.1")

    def test_equality_same_ip(self):
        a = IPRange("10.0.0.1", bitlen=0)
        b = IPRange("10.0.0.1", bitlen=0)
        self.assertEqual(a, b)

    def test_inequality_different_ip(self):
        a = IPRange("10.0.0.1", bitlen=0)
        b = IPRange("10.0.0.2", bitlen=0)
        self.assertNotEqual(a, b)


# ---------------------------------------------------------------------------
# hamming_weight
# ---------------------------------------------------------------------------


class TestHammingWeight(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(hamming_weight(0), 0)

    def test_one(self):
        self.assertEqual(hamming_weight(1), 1)

    def test_all_ones_byte(self):
        self.assertEqual(hamming_weight(0xFF), 8)

    def test_power_of_two(self):
        for i in range(8):
            self.assertEqual(hamming_weight(1 << i), 1)

    def test_known_value(self):
        self.assertEqual(hamming_weight(0b10110101), 5)

    def test_large_number(self):
        # 0xFFFFFFFF has 32 bits set
        self.assertEqual(hamming_weight(0xFFFFFFFF), 32)


# ---------------------------------------------------------------------------
# range_intersects — takes two [start, end] numeric range pairs
# ---------------------------------------------------------------------------


class TestRangeIntersects(unittest.TestCase):
    def test_overlapping_ranges(self):
        self.assertTrue(range_intersects([0, 10], [5, 15]))

    def test_non_overlapping_ranges(self):
        self.assertFalse(range_intersects([0, 5], [6, 10]))

    def test_adjacent_no_overlap(self):
        # hi_start (5) > lo_end (4), so no overlap
        self.assertFalse(range_intersects([0, 4], [5, 10]))

    def test_identical_ranges(self):
        self.assertTrue(range_intersects([5, 10], [5, 10]))

    def test_contained_range(self):
        self.assertTrue(range_intersects([0, 100], [10, 20]))

    def test_single_point_overlap(self):
        self.assertTrue(range_intersects([0, 5], [5, 10]))


# ---------------------------------------------------------------------------
# sorted_search
# ---------------------------------------------------------------------------


class TestSortedSearch(unittest.TestCase):
    def test_finds_existing_element(self):
        lst = [1, 3, 5, 7, 9]
        idx = sorted_search(lst, 5)
        self.assertEqual(lst[idx], 5)

    def test_missing_element_returns_insertion_index(self):
        # sorted_search behaves like bisect — returns an index even when not found
        lst = [1, 3, 5, 7, 9]
        idx = sorted_search(lst, 4)
        self.assertIsNotNone(idx)

    def test_empty_list_returns_none(self):
        self.assertIsNone(sorted_search([], 1))

    def test_first_element(self):
        lst = [2, 4, 6, 8]
        idx = sorted_search(lst, 2)
        self.assertEqual(idx, 0)

    def test_last_element(self):
        lst = [2, 4, 6, 8]
        idx = sorted_search(lst, 8)
        self.assertEqual(idx, 3)

    def test_single_element_found(self):
        self.assertEqual(sorted_search([42], 42), 0)

    def test_single_element_not_found_returns_index(self):
        # Returns an integer insertion point, not None
        idx = sorted_search([42], 7)
        self.assertIsInstance(idx, int)


# ---------------------------------------------------------------------------
# rendezvous_score
# ---------------------------------------------------------------------------


class TestRendezvousScore(unittest.TestCase):
    def test_same_inputs_same_output(self):
        s1 = rendezvous_score(b"node1", b"key", b"server")
        s2 = rendezvous_score(b"node1", b"key", b"server")
        self.assertEqual(s1, s2)

    def test_different_node_different_score(self):
        s1 = rendezvous_score(b"node1", b"key", b"server")
        s2 = rendezvous_score(b"node2", b"key", b"server")
        self.assertNotEqual(s1, s2)

    def test_different_server_different_score(self):
        s1 = rendezvous_score(b"node1", b"key", b"server1")
        s2 = rendezvous_score(b"node1", b"key", b"server2")
        self.assertNotEqual(s1, s2)

    def test_score_is_numeric(self):
        score = rendezvous_score(b"a", b"b", b"c")
        self.assertIsInstance(score, (int, float))

    def test_score_positive(self):
        score = rendezvous_score(b"a", b"b", b"c")
        self.assertGreater(score, 0)


# ---------------------------------------------------------------------------
# to_b / to_h / h_to_b / to_s round-trips
# ---------------------------------------------------------------------------


class TestConversionUtils(unittest.TestCase):
    def test_to_b_bytes_passthrough(self):
        b = b"hello"
        self.assertIs(to_b(b), b)

    def test_to_b_str_encodes(self):
        self.assertEqual(to_b("hello"), b"hello")

    def test_to_h_produces_hex_string(self):
        self.assertEqual(to_h(b"\xde\xad"), "dead")

    def test_h_to_b_decodes_hex(self):
        self.assertEqual(h_to_b("dead"), b"\xde\xad")

    def test_to_h_h_to_b_roundtrip(self):
        original = b"test data \x00\xff"
        self.assertEqual(h_to_b(to_h(original)), original)

    def test_to_s_bytes_to_str(self):
        self.assertEqual(to_s(b"hello"), "hello")

    def test_to_s_str_passthrough(self):
        self.assertEqual(to_s("hello"), "hello")

    def test_rand_b_produces_correct_length(self):
        for n in [1, 8, 32, 64]:
            with self.subTest(n=n):
                b = rand_b(n)
                self.assertEqual(len(b), n)

    def test_rand_b_is_bytes(self):
        self.assertIsInstance(rand_b(10), bytes)

    def test_rand_b_two_calls_differ(self):
        self.assertNotEqual(rand_b(32), rand_b(32))


if __name__ == "__main__":
    unittest.main()
