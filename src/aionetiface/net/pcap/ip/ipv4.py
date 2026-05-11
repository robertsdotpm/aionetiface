"""RFC 791 IPv4 header pack/parse + 1's-complement checksum.

Pure-protocol code -- no ctypes, importable everywhere.

Wire format (no options):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver=4| IHL |TOS/DSCP|         Total Length                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Identification         |Flags|     Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    TTL        |   Protocol    |        Header Checksum        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Address                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Destination Address                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

References:
  - RFC 791 -- Internet Protocol:
    https://datatracker.ietf.org/doc/html/rfc791
  - RFC 1071 -- 1's-complement checksum algorithm:
    https://datatracker.ietf.org/doc/html/rfc1071
"""
import socket
import struct


IPV4_HDR_LEN = 20  # no options

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

FLAG_DF = 0x4000  # Don't Fragment
FLAG_MF = 0x2000  # More Fragments


def checksum16(data):
    """RFC 1071 1's-complement checksum over `data` bytes.

    Returns a 16-bit integer suitable to drop into the IPv4 header
    checksum field (or the TCP/UDP segment checksum field once you've
    pre-computed it with the pseudo-header).
    """
    buf = bytes(data)
    if len(buf) & 1:
        buf = buf + b"\x00"  # zero-pad to a 16-bit boundary
    total = 0
    for i in range(0, len(buf), 2):
        total += (buf[i] << 8) | buf[i + 1]
        # Fold carry every iteration so we never overflow 32-bit on Py2;
        # cheap on Py3 too.
        total = (total & 0xffff) + (total >> 16)
    # Final fold + 1's-complement.
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def pack_ipv4(src_ip, dst_ip, proto, payload, ident=0, ttl=64,
              tos=0, flags=FLAG_DF, frag_offset=0):
    """Pack an IPv4 header + payload.

    src_ip / dst_ip accept dotted-quad strings or 4-byte addresses.
    payload is the L4 segment bytes (TCP/UDP/ICMP); pack_ipv4 fills in
    the Total Length, Header Checksum, and emits the full IP datagram.
    """
    if isinstance(src_ip, str):
        src = socket.inet_aton(src_ip)
    else:
        src = bytes(src_ip)
    if isinstance(dst_ip, str):
        dst = socket.inet_aton(dst_ip)
    else:
        dst = bytes(dst_ip)
    if len(src) != 4 or len(dst) != 4:
        raise ValueError("ipv4 addresses must be 4 bytes")

    total_len = IPV4_HDR_LEN + len(payload)
    ver_ihl = (4 << 4) | 5  # IHL=5 -> 20 bytes
    frag_field = (int(flags) & 0xe000) | (int(frag_offset) & 0x1fff)

    # Build with checksum=0 first, compute, patch.
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, int(tos), total_len, int(ident) & 0xffff,
        frag_field, int(ttl), int(proto), 0, src, dst,
    )
    csum = checksum16(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, int(tos), total_len, int(ident) & 0xffff,
        frag_field, int(ttl), int(proto), csum, src, dst,
    )
    return header + bytes(payload)


class Ipv4Header(object):
    """Parsed IPv4 header.  Field names mirror RFC 791."""

    __slots__ = (
        "version", "ihl", "tos", "total_len", "ident", "flags",
        "frag_offset", "ttl", "proto", "checksum", "src", "dst",
        "header_len", "payload_offset", "raw_header",
    )

    def __init__(self, version, ihl, tos, total_len, ident, flags,
                 frag_offset, ttl, proto, checksum, src, dst,
                 header_len, payload_offset, raw_header):
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.total_len = total_len
        self.ident = ident
        self.flags = flags
        self.frag_offset = frag_offset
        self.ttl = ttl
        self.proto = proto
        self.checksum = checksum
        self.src = src
        self.dst = dst
        self.header_len = header_len
        self.payload_offset = payload_offset
        self.raw_header = raw_header

    @property
    def src_str(self):
        return socket.inet_ntoa(self.src)

    @property
    def dst_str(self):
        return socket.inet_ntoa(self.dst)


def parse_ipv4(packet_bytes):
    """Return (Ipv4Header, payload_bytes) from a complete IP datagram.

    Raises ValueError on malformed input.  Does NOT validate the
    checksum -- caller can call validate_checksum() if desired.
    """
    buf = bytes(packet_bytes)
    if len(buf) < IPV4_HDR_LEN:
        raise ValueError("ipv4 packet shorter than {0} bytes".format(IPV4_HDR_LEN))
    ver_ihl = buf[0]
    version = (ver_ihl >> 4) & 0xf
    ihl = ver_ihl & 0xf
    if version != 4:
        raise ValueError("not an IPv4 packet (version={0})".format(version))
    if ihl < 5:
        raise ValueError("invalid IHL={0}".format(ihl))
    header_len = ihl * 4
    if len(buf) < header_len:
        raise ValueError("ipv4 packet truncated mid-header")

    (_, tos, total_len, ident, frag_field,
     ttl, proto, csum, src, dst) = struct.unpack(
        "!BBHHHBBH4s4s", buf[:IPV4_HDR_LEN])
    flags = frag_field & 0xe000
    frag_offset = frag_field & 0x1fff
    raw_header = buf[:header_len]
    # Trim to total_len so we don't pass loopback FCS padding into TCP.
    if total_len < header_len:
        raise ValueError("ipv4 total_len {0} < header_len {1}".format(
            total_len, header_len))
    payload = buf[header_len:total_len] if total_len <= len(buf) else buf[header_len:]
    hdr = Ipv4Header(
        version=version, ihl=ihl, tos=tos, total_len=total_len,
        ident=ident, flags=flags, frag_offset=frag_offset, ttl=ttl,
        proto=proto, checksum=csum, src=src, dst=dst,
        header_len=header_len, payload_offset=header_len, raw_header=raw_header,
    )
    return hdr, payload


def validate_checksum(packet_bytes):
    """True iff the IPv4 header checksum verifies."""
    buf = bytes(packet_bytes)
    if len(buf) < IPV4_HDR_LEN:
        return False
    ihl = buf[0] & 0xf
    return checksum16(buf[: ihl * 4]) == 0


def pseudo_header_ipv4(src_ip, dst_ip, proto, l4_length):
    """Build the 12-byte IPv4 pseudo-header used by TCP/UDP checksums.

    See RFC 793 section 3.1 (TCP) / RFC 768 (UDP): the L4 checksum is
    computed over (pseudo-header || L4 segment).
    """
    if isinstance(src_ip, str):
        src = socket.inet_aton(src_ip)
    else:
        src = bytes(src_ip)
    if isinstance(dst_ip, str):
        dst = socket.inet_aton(dst_ip)
    else:
        dst = bytes(dst_ip)
    return struct.pack("!4s4sBBH", src, dst, 0, int(proto), int(l4_length))
