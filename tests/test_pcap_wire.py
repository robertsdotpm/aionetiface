"""Wire-format unit tests for the pcap pure-protocol layer.

Tests cover:
    - RFC 1071 checksum (known vectors)
    - IPv4 header pack/parse round-trip + checksum verification
    - TCP segment pack/parse round-trip + pseudo-header checksum
    - Ethernet II frame pack/parse + DLT_NULL strip/wrap helpers
    - ARP request / reply round-trip
    - IPv6 header pack/parse round-trip

No live pcap I/O here -- pure bytes-in, bytes-out.
"""
import struct
import unittest

from aionetiface.testing import AsyncTestCase

from aionetiface.net.pcap.ip.ipv4 import (
    checksum16, pack_ipv4, parse_ipv4, validate_checksum, pseudo_header_ipv4,
    PROTO_TCP,
)
from aionetiface.net.pcap.ip.ipv6 import (
    pack_ipv6, parse_ipv6, pseudo_header_ipv6,
)
from aionetiface.net.pcap.ip.eth import (
    build_eth_frame, parse_eth_frame, build_arp_request, build_arp_reply,
    parse_arp, ArpCache, strip_link_layer, wrap_link_layer,
    ETH_TYPE_IPV4, ETH_TYPE_ARP, ARP_OP_REQUEST, ARP_OP_REPLY,
    parse_mac, format_mac,
)
from aionetiface.net.pcap.tcp.segment import (
    TcpSegment, pack_tcp_segment, parse_tcp_segment, validate_checksum as tcp_validate,
    FLAG_SYN, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST,
    build_mss_option, parse_options, get_option, OPT_MSS,
)


class TestChecksum16(AsyncTestCase):
    """RFC 1071 vectors."""

    async def test_zero_buffer(self):
        # All zeros -> 0xffff (one's complement of 0)
        self.assertEqual(checksum16(b"\x00" * 20), 0xffff)

    async def test_rfc1071_example(self):
        # RFC 1071 sec 3 example: 0001 f203 f4f5 f6f7 -> sum=0xddf2,
        # 1's-comp = 0x220d.
        data = b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"
        self.assertEqual(checksum16(data), 0x220d)

    async def test_odd_length(self):
        # Odd-length input must zero-pad.  ([0x01]) zero-padded
        # = [0x01, 0x00] -> sum 0x0100 -> 1c = 0xfeff
        self.assertEqual(checksum16(b"\x01"), 0xfeff)


class TestIpv4Wire(AsyncTestCase):

    async def test_roundtrip_basic(self):
        payload = b"hello pcap"
        pkt = pack_ipv4("10.0.0.1", "10.0.0.2", PROTO_TCP, payload, ident=0xbeef)
        self.assertTrue(validate_checksum(pkt))
        hdr, parsed_payload = parse_ipv4(pkt)
        self.assertEqual(hdr.version, 4)
        self.assertEqual(hdr.ihl, 5)
        self.assertEqual(hdr.proto, PROTO_TCP)
        self.assertEqual(hdr.src_str, "10.0.0.1")
        self.assertEqual(hdr.dst_str, "10.0.0.2")
        self.assertEqual(hdr.ident, 0xbeef)
        self.assertEqual(parsed_payload, payload)

    async def test_total_len_trim(self):
        # Trailing garbage bytes after total_len must be ignored.
        payload = b"x" * 16
        pkt = pack_ipv4("1.2.3.4", "5.6.7.8", 17, payload)
        garbage = pkt + b"\xaa\xbb\xcc"
        hdr, parsed = parse_ipv4(garbage)
        self.assertEqual(parsed, payload)
        self.assertEqual(hdr.total_len, 20 + len(payload))

    async def test_bad_version_rejected(self):
        pkt = bytearray(pack_ipv4("1.1.1.1", "2.2.2.2", 6, b"x"))
        pkt[0] = (5 << 4) | 5  # version=5
        with self.assertRaises(ValueError):
            parse_ipv4(bytes(pkt))

    async def test_pseudo_header_shape(self):
        ph = pseudo_header_ipv4("10.0.0.1", "10.0.0.2", 6, 24)
        self.assertEqual(len(ph), 12)
        # bytes: src(4) | dst(4) | 0 | proto | length(2)
        self.assertEqual(ph[8], 0)
        self.assertEqual(ph[9], 6)
        self.assertEqual(struct.unpack("!H", ph[10:12])[0], 24)


class TestTcpSegmentWire(AsyncTestCase):

    async def test_roundtrip_syn(self):
        seg = TcpSegment(
            src_port=1234, dst_port=80, seq=100, ack=0,
            flags=FLAG_SYN, window=65535,
            options=build_mss_option(1460),
        )
        wire = pack_tcp_segment(seg, "10.0.0.1", "10.0.0.2")
        self.assertTrue(tcp_validate(wire, "10.0.0.1", "10.0.0.2"))
        parsed = parse_tcp_segment(wire)
        self.assertEqual(parsed.src_port, 1234)
        self.assertEqual(parsed.dst_port, 80)
        self.assertEqual(parsed.seq, 100)
        self.assertEqual(parsed.flags, FLAG_SYN)
        opts = parse_options(parsed.options)
        mss = get_option(opts, OPT_MSS)
        self.assertIsNotNone(mss)
        self.assertEqual(struct.unpack("!H", mss)[0], 1460)

    async def test_roundtrip_data(self):
        payload = b"X" * 100
        seg = TcpSegment(
            src_port=4444, dst_port=5555, seq=1000, ack=2000,
            flags=FLAG_ACK | FLAG_PSH, payload=payload,
        )
        wire = pack_tcp_segment(seg, "192.168.1.10", "192.168.1.20")
        self.assertTrue(tcp_validate(wire, "192.168.1.10", "192.168.1.20"))
        parsed = parse_tcp_segment(wire)
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(parsed.seq, 1000)
        self.assertEqual(parsed.ack, 2000)
        self.assertTrue(parsed.has_flag(FLAG_PSH))
        self.assertTrue(parsed.has_flag(FLAG_ACK))

    async def test_segment_length_seq_consumes(self):
        syn = TcpSegment(flags=FLAG_SYN, payload=b"")
        self.assertEqual(syn.segment_length(), 1)
        fin = TcpSegment(flags=FLAG_FIN, payload=b"")
        self.assertEqual(fin.segment_length(), 1)
        synfin = TcpSegment(flags=FLAG_SYN | FLAG_FIN, payload=b"abc")
        self.assertEqual(synfin.segment_length(), 5)
        rst = TcpSegment(flags=FLAG_RST, payload=b"")
        self.assertEqual(rst.segment_length(), 0)

    async def test_corrupt_segment_invalidates(self):
        seg = TcpSegment(
            src_port=1, dst_port=2, seq=0, ack=0, flags=FLAG_ACK,
            payload=b"hi",
        )
        wire = bytearray(pack_tcp_segment(seg, "1.1.1.1", "2.2.2.2"))
        wire[-1] ^= 0xff
        self.assertFalse(tcp_validate(bytes(wire), "1.1.1.1", "2.2.2.2"))


class TestEthernetWire(AsyncTestCase):

    async def test_mac_parse_format(self):
        m = parse_mac("aa:bb:cc:11:22:33")
        self.assertEqual(m, b"\xaa\xbb\xcc\x11\x22\x33")
        self.assertEqual(format_mac(m), "aa:bb:cc:11:22:33")

    async def test_mac_bad_input(self):
        with self.assertRaises(ValueError):
            parse_mac("aa:bb:cc:dd:ee")
        with self.assertRaises(ValueError):
            parse_mac("not a mac at all")

    async def test_eth_frame_roundtrip(self):
        payload = b"the payload" + b"\x00" * 30
        frame = build_eth_frame(
            "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, payload)
        dst, src, et, pay = parse_eth_frame(frame)
        self.assertEqual(dst, b"\x00\x11\x22\x33\x44\x55")
        self.assertEqual(src, b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(et, 0x0800)
        # The wrapper pads short frames to 60 bytes; payload prefix matches.
        self.assertTrue(pay.startswith(payload))

    async def test_strip_wrap_en10mb(self):
        from aionetiface.net.pcap.os.libpcap_core import DLT_EN10MB
        ip_payload = b"FAKE_IP_DATAGRAM" * 4
        frame = wrap_link_layer(
            DLT_EN10MB, ETH_TYPE_IPV4,
            "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", ip_payload)
        et, payload = strip_link_layer(DLT_EN10MB, frame)
        self.assertEqual(et, ETH_TYPE_IPV4)
        self.assertTrue(payload.startswith(ip_payload))

    async def test_strip_wrap_dlt_null(self):
        from aionetiface.net.pcap.os.libpcap_core import DLT_NULL
        ip_payload = b"\x45\x00" + b"\xab" * 20  # looks like IPv4-ish bytes
        frame = wrap_link_layer(DLT_NULL, ETH_TYPE_IPV4, None, None, ip_payload)
        # 4-byte AF prefix + payload
        self.assertEqual(len(frame), 4 + len(ip_payload))
        et, payload = strip_link_layer(DLT_NULL, frame)
        self.assertEqual(et, ETH_TYPE_IPV4)
        self.assertEqual(payload, ip_payload)


class TestArpWire(AsyncTestCase):

    async def test_request_roundtrip(self):
        frame = build_arp_request(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", "10.0.0.6")
        dst, src, et, payload = parse_eth_frame(frame)
        self.assertEqual(et, ETH_TYPE_ARP)
        # Broadcast destination on request.
        self.assertEqual(dst, b"\xff\xff\xff\xff\xff\xff")
        parsed = parse_arp(payload)
        self.assertIsNotNone(parsed)
        op, smac, sip, tmac, tip = parsed
        self.assertEqual(op, ARP_OP_REQUEST)
        self.assertEqual(smac, b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(sip, b"\x0a\x00\x00\x05")
        self.assertEqual(tip, b"\x0a\x00\x00\x06")

    async def test_reply_roundtrip(self):
        frame = build_arp_reply(
            sender_mac="11:22:33:44:55:66", sender_ip="10.0.0.7",
            target_mac="aa:bb:cc:dd:ee:ff", target_ip="10.0.0.5",
        )
        _, _, et, payload = parse_eth_frame(frame)
        self.assertEqual(et, ETH_TYPE_ARP)
        op, smac, sip, tmac, tip = parse_arp(payload)
        self.assertEqual(op, ARP_OP_REPLY)
        self.assertEqual(smac, b"\x11\x22\x33\x44\x55\x66")

    async def test_arp_cache_learns(self):
        cache = ArpCache(ttl_seconds=5)
        # Build an ARP reply 'announce' and let the cache learn it.
        frame = build_arp_reply(
            "11:22:33:44:55:66", "10.0.0.7",
            "aa:bb:cc:dd:ee:ff", "10.0.0.5",
        )
        _, _, et, payload = parse_eth_frame(frame)
        self.assertTrue(cache.feed_arp(payload))
        self.assertEqual(cache.get("10.0.0.7"),
                         b"\x11\x22\x33\x44\x55\x66")
        self.assertEqual(cache.get("10.0.0.5"),
                         b"\xaa\xbb\xcc\xdd\xee\xff")


class TestIpv6Wire(AsyncTestCase):

    async def test_roundtrip(self):
        payload = b"v6 tcp segment goes here"
        pkt = pack_ipv6("::1", "::2", 6, payload, hop_limit=64)
        hdr, parsed = parse_ipv6(pkt)
        self.assertEqual(hdr["version"], 6)
        self.assertEqual(hdr["next_header"], 6)
        self.assertEqual(hdr["hop_limit"], 64)
        self.assertEqual(parsed, payload)

    async def test_pseudo_header_v6_shape(self):
        ph = pseudo_header_ipv6("::1", "::2", 6, 40)
        self.assertEqual(len(ph), 40)


if __name__ == "__main__":
    unittest.main()
