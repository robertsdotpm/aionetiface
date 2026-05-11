"""RFC 8200 IPv6 header pack/parse -- skeleton.

The Phase-2 mandate is IPv4 simultaneous-open on XP, so IPv6 is here in
skeleton form only.  When v6 punching ships, the same TCP segment +
state-machine code reuses these helpers via pseudo_header_ipv6().

Wire format (no extension headers):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver=6|TrafClass|             Flow Label                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Payload Length              | Next Header   |  Hop Limit    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address (16 bytes)               |
   |                       Destination Address (16 bytes)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

References:
  - RFC 8200 -- Internet Protocol, Version 6 (IPv6) Specification:
    https://datatracker.ietf.org/doc/html/rfc8200
  - RFC 2460 (obsoleted by 8200) for the pseudo-header definition that
    TCP/UDP checksums use.
"""
import socket
import struct


IPV6_HDR_LEN = 40

NEXT_HEADER_TCP = 6
NEXT_HEADER_UDP = 17
NEXT_HEADER_ICMPV6 = 58


def addr16(addr):
    """Accept dotted/colon string or 16-byte bytes, return 16 bytes."""
    if isinstance(addr, (bytes, bytearray)) and len(addr) == 16:
        return bytes(addr)
    if not isinstance(addr, str):
        raise ValueError("ipv6 address must be string or 16 bytes")
    return socket.inet_pton(socket.AF_INET6, addr)


def pack_ipv6(src_ip, dst_ip, next_header, payload, hop_limit=64,
              traffic_class=0, flow_label=0):
    """Pack an IPv6 datagram (no extension headers)."""
    src = addr16(src_ip)
    dst = addr16(dst_ip)
    ver_tc_fl = (6 << 28) | ((int(traffic_class) & 0xff) << 20) | (int(flow_label) & 0xfffff)
    header = struct.pack(
        "!IHBB16s16s",
        ver_tc_fl,
        len(payload),
        int(next_header),
        int(hop_limit),
        src, dst,
    )
    return header + bytes(payload)


def parse_ipv6(packet_bytes):
    """Return (header_dict, payload_bytes).  Minimal -- ignores extension
    header chains, which we don't generate for tcp_punch."""
    buf = bytes(packet_bytes)
    if len(buf) < IPV6_HDR_LEN:
        raise ValueError("ipv6 packet shorter than {0} bytes".format(IPV6_HDR_LEN))
    ver_tc_fl, payload_len, next_header, hop_limit, src, dst = struct.unpack(
        "!IHBB16s16s", buf[:IPV6_HDR_LEN])
    version = (ver_tc_fl >> 28) & 0xf
    if version != 6:
        raise ValueError("not an IPv6 packet (version={0})".format(version))
    payload = buf[IPV6_HDR_LEN:IPV6_HDR_LEN + payload_len]
    return {
        "version": version,
        "traffic_class": (ver_tc_fl >> 20) & 0xff,
        "flow_label": ver_tc_fl & 0xfffff,
        "payload_len": payload_len,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "src": src,
        "dst": dst,
    }, payload


def pseudo_header_ipv6(src_ip, dst_ip, next_header, l4_length):
    """RFC 8200 IPv6 pseudo-header for TCP/UDP checksums.

    Structure: src(16) | dst(16) | length(4) | zeros(3) | next_hdr(1).
    """
    src = addr16(src_ip)
    dst = addr16(dst_ip)
    return struct.pack(
        "!16s16sI3xB", src, dst, int(l4_length), int(next_header))
