"""RFC 9293 TCP segment pack/parse + checksum.

Pure-protocol code -- no ctypes, no I/O.  Importable on every platform.

Wire format:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Source Port           |     Destination Port            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Sequence Number                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Data |Reservd|U|A|P|R|S|F|        Window                      |
   | Off  |       |R|C|S|S|Y|I|                                    |
   |      |       |G|K|H|T|N|N|                                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Checksum             |        Urgent Pointer         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     (Options + Padding)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              Data                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

References:
  - RFC 9293 -- Transmission Control Protocol (TCP):
    https://datatracker.ietf.org/doc/html/rfc9293
  - Section 3.1 for segment format; section 3.4 for checksum (which
    includes the IP pseudo-header per RFC 793).
"""
import struct

from ..ip.ipv4 import checksum16, pseudo_header_ipv4
from ..ip.ipv6 import pseudo_header_ipv6


TCP_HDR_MIN = 20

# Flag bits per RFC 9293 sec 3.1.
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80

# Option kinds (RFC 9293 sec 3.2).
OPT_EOL = 0
OPT_NOP = 1
OPT_MSS = 2
OPT_WSCALE = 3
OPT_SACKPERM = 4
OPT_SACK = 5
OPT_TIMESTAMP = 8


class TcpSegment(object):
    """Parsed or in-construction TCP segment.

    Carries the fields exactly as they appear on the wire; the state
    machine reads / writes via attribute access.  data_offset is in
    32-bit words per the wire encoding -- header_len_bytes() converts.
    """

    __slots__ = (
        "src_port", "dst_port", "seq", "ack", "data_offset", "flags",
        "window", "checksum", "urgent", "options", "payload",
    )

    def __init__(self, src_port=0, dst_port=0, seq=0, ack=0, flags=0,
                 window=65535, options=b"", payload=b"", urgent=0):
        self.src_port = int(src_port)
        self.dst_port = int(dst_port)
        self.seq = int(seq) & 0xffffffff
        self.ack = int(ack) & 0xffffffff
        self.flags = int(flags) & 0xff
        self.window = int(window) & 0xffff
        self.options = bytes(options)
        self.payload = bytes(payload)
        self.urgent = int(urgent) & 0xffff
        # data_offset & checksum are set at pack/parse time.
        self.data_offset = (TCP_HDR_MIN + len(self.options) + 3) // 4
        self.checksum = 0

    def has_flag(self, mask):
        return bool(self.flags & mask)

    def header_len_bytes(self):
        return self.data_offset * 4

    def segment_length(self):
        """SYN and FIN each consume one sequence number per RFC 9293
        section 3.4; this property is what advances seq across a
        transmit / receive."""
        n = len(self.payload)
        if self.flags & FLAG_SYN:
            n += 1
        if self.flags & FLAG_FIN:
            n += 1
        return n

    def __repr__(self):
        names = []
        for name, mask in (("FIN", FLAG_FIN), ("SYN", FLAG_SYN),
                           ("RST", FLAG_RST), ("PSH", FLAG_PSH),
                           ("ACK", FLAG_ACK), ("URG", FLAG_URG)):
            if self.flags & mask:
                names.append(name)
        return "TcpSegment(src={0} dst={1} seq={2} ack={3} flags={4} win={5} data={6}B)".format(
            self.src_port, self.dst_port, self.seq, self.ack,
            "|".join(names) or "0", self.window, len(self.payload))


def pad_options(options):
    """Pad options to a 32-bit boundary with NOPs (0x01)."""
    opts = bytes(options)
    pad = (4 - (len(opts) % 4)) % 4
    if pad:
        opts = opts + (b"\x01" * pad)
    return opts


def build_mss_option(mss):
    """Encode the MSS option (kind=2, len=4)."""
    return struct.pack("!BBH", OPT_MSS, 4, int(mss) & 0xffff)


def parse_options(opt_bytes):
    """Return a list of (kind, data_bytes) tuples.  NOPs and EOL are
    included as zero-data entries so callers can preserve ordering when
    re-encoding."""
    out = []
    i = 0
    buf = bytes(opt_bytes)
    while i < len(buf):
        kind = buf[i]
        if kind == OPT_EOL:
            out.append((OPT_EOL, b""))
            break
        if kind == OPT_NOP:
            out.append((OPT_NOP, b""))
            i += 1
            continue
        if i + 1 >= len(buf):
            break
        length = buf[i + 1]
        if length < 2 or i + length > len(buf):
            break
        out.append((kind, buf[i + 2: i + length]))
        i += length
    return out


def get_option(parsed_opts, kind):
    """Find the first option of `kind` and return its data, or None."""
    for k, data in parsed_opts:
        if k == kind:
            return data
    return None


def pack_tcp_segment(segment, src_ip, dst_ip, ipv6=False):
    """Serialise a TcpSegment to wire bytes, computing the checksum
    over the right pseudo-header.

    src_ip / dst_ip are the IP endpoints used to seed the pseudo-header.
    """
    opts = pad_options(segment.options)
    data_offset = (TCP_HDR_MIN + len(opts)) // 4
    if data_offset > 15:
        raise ValueError("TCP header too long (options > 40 bytes)")
    segment.data_offset = data_offset
    off_resv_flags = (data_offset << 12) | (segment.flags & 0xff)
    head_no_csum = struct.pack(
        "!HHIIHHHH",
        segment.src_port, segment.dst_port,
        segment.seq, segment.ack,
        off_resv_flags, segment.window, 0, segment.urgent,
    ) + opts
    body = head_no_csum + segment.payload
    if ipv6:
        ph = pseudo_header_ipv6(src_ip, dst_ip, 6, len(body))
    else:
        ph = pseudo_header_ipv4(src_ip, dst_ip, 6, len(body))
    csum = checksum16(ph + body)
    segment.checksum = csum
    head_with_csum = struct.pack(
        "!HHIIHHHH",
        segment.src_port, segment.dst_port,
        segment.seq, segment.ack,
        off_resv_flags, segment.window, csum, segment.urgent,
    ) + opts
    return head_with_csum + segment.payload


def parse_tcp_segment(buf):
    """Parse wire bytes into a TcpSegment.  Caller verifies the
    checksum separately if needed (we keep parsing tolerant so a
    corrupt segment doesn't blow up the reader thread)."""
    if len(buf) < TCP_HDR_MIN:
        raise ValueError("tcp segment shorter than {0} bytes".format(TCP_HDR_MIN))
    (src_port, dst_port, seq, ack, off_resv_flags,
     window, csum, urgent) = struct.unpack("!HHIIHHHH", bytes(buf[:TCP_HDR_MIN]))
    data_offset = (off_resv_flags >> 12) & 0xf
    flags = off_resv_flags & 0xff
    if data_offset < 5:
        raise ValueError("invalid TCP data offset {0}".format(data_offset))
    hdr_len = data_offset * 4
    if len(buf) < hdr_len:
        raise ValueError("tcp segment truncated mid-header")
    options = bytes(buf[TCP_HDR_MIN: hdr_len])
    payload = bytes(buf[hdr_len:])
    seg = TcpSegment(
        src_port=src_port, dst_port=dst_port, seq=seq, ack=ack,
        flags=flags, window=window, options=options, payload=payload,
        urgent=urgent,
    )
    seg.data_offset = data_offset
    seg.checksum = csum
    return seg


def validate_checksum(buf, src_ip, dst_ip, ipv6=False):
    """True iff the segment checksum verifies against pseudo-header."""
    if len(buf) < TCP_HDR_MIN:
        return False
    if ipv6:
        ph = pseudo_header_ipv6(src_ip, dst_ip, 6, len(buf))
    else:
        ph = pseudo_header_ipv4(src_ip, dst_ip, 6, len(buf))
    return checksum16(ph + bytes(buf)) == 0
