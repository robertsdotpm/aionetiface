"""Ethernet II framing + ARP for next-hop MAC lookup.

Pure-protocol code -- no ctypes, no DLL loading.  Importable on every
platform; the only thing this module does is pack/unpack bytes and
maintain a tiny ARP cache.

References:
  - IEEE 802.3 Ethernet II / DIX framing:
    https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
  - RFC 826 -- Address Resolution Protocol (ARP):
    https://datatracker.ietf.org/doc/html/rfc826

Wire format (DLT_EN10MB):
    0      6     12      14        N
    +------+-----+-------+----------+
    |dst_mac|src_mac|ethertype| payload |
    +------+-----+-------+----------+
    each MAC is 6 bytes; ethertype is 2 bytes big-endian.

Note:
  - DLT_NULL (BSD loopback) uses a 4-byte AF_* prefix instead, handled
    in ipv4.py / ipv6.py at the IP-layer entrypoint (the Ethernet
    header is simply absent).  See `is_link_layer_ethernet()` below.
  - We do not implement 802.1Q VLAN tagging -- tcp_punch traffic on
    XP-era NICs does not need it.
"""
import struct


ETH_HDR_LEN = 14
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV6 = 0x86DD

ARP_HW_ETHER = 1
ARP_PROTO_IPV4 = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

# Broadcast / unspecified MACs we'll need to recognise everywhere.
MAC_BROADCAST = b"\xff\xff\xff\xff\xff\xff"
MAC_ZERO = b"\x00\x00\x00\x00\x00\x00"


def parse_mac(text):
    """Parse a colon-separated MAC string into 6 bytes.  Accepts upper
    or lower hex; rejects anything that does not produce exactly six
    octets."""
    if isinstance(text, (bytes, bytearray)) and len(text) == 6:
        return bytes(text)
    if not isinstance(text, str):
        raise ValueError("mac must be 'xx:xx:xx:xx:xx:xx' string")
    parts = text.split(":")
    if len(parts) != 6:
        raise ValueError("mac string has {0} parts, want 6".format(len(parts)))
    try:
        return bytes(bytearray(int(p, 16) for p in parts))
    except ValueError:
        raise ValueError("mac string has non-hex byte: {0}".format(text))


def format_mac(raw):
    """6-byte bytes -> 'aa:bb:cc:dd:ee:ff' lowercase."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6:
        raise ValueError("mac bytes must be exactly 6 octets")
    return ":".join("{0:02x}".format(b) for b in bytearray(raw))


def build_eth_frame(dst_mac, src_mac, ethertype, payload):
    """Pack a DLT_EN10MB frame.  Caller supplies finished payload bytes
    (IPv4 packet, ARP packet, etc.).  Pads short frames to the 60-byte
    Ethernet minimum so loopback drivers don't reject them."""
    if isinstance(dst_mac, str):
        dst_mac = parse_mac(dst_mac)
    if isinstance(src_mac, str):
        src_mac = parse_mac(src_mac)
    if len(dst_mac) != 6 or len(src_mac) != 6:
        raise ValueError("eth mac fields must be 6 bytes each")
    head = struct.pack("!6s6sH", bytes(dst_mac), bytes(src_mac), int(ethertype))
    frame = head + bytes(payload)
    if len(frame) < 60:
        frame = frame + b"\x00" * (60 - len(frame))
    return frame


def parse_eth_frame(frame_bytes):
    """Return (dst_mac, src_mac, ethertype, payload) or raise ValueError.

    We accept any frame >= 14 bytes; FCS is stripped by libpcap before we
    see the frame on every datalink we touch."""
    if len(frame_bytes) < ETH_HDR_LEN:
        raise ValueError("eth frame shorter than {0} bytes".format(ETH_HDR_LEN))
    dst_mac, src_mac, ethertype = struct.unpack(
        "!6s6sH", bytes(frame_bytes[:ETH_HDR_LEN]))
    return dst_mac, src_mac, ethertype, bytes(frame_bytes[ETH_HDR_LEN:])


def is_link_layer_ethernet(dlt):
    """True iff the datalink type uses 14-byte Ethernet II framing."""
    from ..os.libpcap_core import DLT_EN10MB
    return dlt == DLT_EN10MB


def strip_link_layer(dlt, frame_bytes):
    """Strip whatever link-layer header is in front of the IP packet.

    Returns (ethertype_or_af, payload_bytes).  The caller uses
    ethertype_or_af to branch IPv4 vs IPv6 vs ARP.

    DLT_EN10MB returns the real ethertype (0x0800 etc).
    DLT_NULL / DLT_LOOP return AF_INET / AF_INET6 mapped to a virtual
        ethertype so downstream code can stay uniform.
    """
    from ..os.libpcap_core import DLT_EN10MB, DLT_NULL, DLT_LOOP
    if dlt == DLT_EN10MB:
        _, _, et, payload = parse_eth_frame(frame_bytes)
        return et, payload
    if dlt == DLT_NULL:
        # BSD loopback: 4-byte AF_* in *host* byte order.  On every
        # little-endian box we test on, AF_INET = 2 lands as 02 00 00 00.
        # On big-endian (hypothetical) it would land as 00 00 00 02; we
        # accept both by testing both ends and picking the one that
        # matches a known AF_* constant.
        if len(frame_bytes) < 4:
            raise ValueError("DLT_NULL frame shorter than 4 bytes")
        head = bytes(frame_bytes[:4])
        af_le = struct.unpack("<I", head)[0]
        af_be = struct.unpack(">I", head)[0]
        # AF_INET=2 on every Unix; AF_INET6 varies (BSD 28/30, Linux 10)
        # but Linux doesn't use DLT_NULL so the BSD numbers apply.
        if af_le == 2:
            return ETH_TYPE_IPV4, bytes(frame_bytes[4:])
        if af_be == 2:
            return ETH_TYPE_IPV4, bytes(frame_bytes[4:])
        if af_le in (24, 28, 30):
            return ETH_TYPE_IPV6, bytes(frame_bytes[4:])
        if af_be in (24, 28, 30):
            return ETH_TYPE_IPV6, bytes(frame_bytes[4:])
        raise ValueError("DLT_NULL: unrecognised AF prefix {0:#x}".format(af_le))
    if dlt == DLT_LOOP:
        # OpenBSD: 4-byte AF_* in big-endian.
        if len(frame_bytes) < 4:
            raise ValueError("DLT_LOOP frame shorter than 4 bytes")
        af = struct.unpack(">I", bytes(frame_bytes[:4]))[0]
        if af == 2:
            return ETH_TYPE_IPV4, bytes(frame_bytes[4:])
        if af in (24, 28, 30):
            return ETH_TYPE_IPV6, bytes(frame_bytes[4:])
        raise ValueError("DLT_LOOP: unrecognised AF prefix {0:#x}".format(af))
    raise ValueError("unsupported datalink type {0}".format(dlt))


def wrap_link_layer(dlt, ethertype, dst_mac, src_mac, payload):
    """Inverse of strip_link_layer -- prepend whatever link-layer header
    the datalink needs in front of `payload`.

    dst_mac / src_mac are ignored on DLT_NULL / DLT_LOOP (no MACs there).
    """
    from ..os.libpcap_core import DLT_EN10MB, DLT_NULL, DLT_LOOP
    if dlt == DLT_EN10MB:
        return build_eth_frame(dst_mac, src_mac, ethertype, payload)
    if dlt == DLT_NULL:
        # Host-endian AF_*.  We default to little-endian since every
        # box we currently run on is LE; the parser side accepts both.
        if ethertype == ETH_TYPE_IPV4:
            af = 2
        elif ethertype == ETH_TYPE_IPV6:
            # macOS uses AF_INET6=30; FreeBSD 28.  Either round-trips
            # through strip_link_layer.  Use 30 for the common macOS
            # path.
            af = 30
        else:
            raise ValueError("DLT_NULL only carries IPv4 / IPv6")
        return struct.pack("<I", af) + bytes(payload)
    if dlt == DLT_LOOP:
        if ethertype == ETH_TYPE_IPV4:
            af = 2
        elif ethertype == ETH_TYPE_IPV6:
            af = 24  # OpenBSD AF_INET6
        else:
            raise ValueError("DLT_LOOP only carries IPv4 / IPv6")
        return struct.pack(">I", af) + bytes(payload)
    raise ValueError("unsupported datalink type {0}".format(dlt))


# --- ARP (only used to learn the next-hop MAC for IPv4 punching) ---


def build_arp_request(sender_mac, sender_ip, target_ip):
    """Pack an Ethernet+ARP request asking 'who has target_ip?'.

    sender_mac / sender_ip are ours; target_ip is the host we're trying
    to learn the MAC of.  Returns the full Ethernet frame (broadcast).

    Input IPs as `bytes` (4 bytes) or dotted-quad string.
    """
    smac = parse_mac(sender_mac) if isinstance(sender_mac, str) else sender_mac
    sip = ip_to_bytes4(sender_ip)
    tip = ip_to_bytes4(target_ip)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HW_ETHER, ARP_PROTO_IPV4,
        6, 4, ARP_OP_REQUEST,
        smac, sip, MAC_ZERO, tip,
    )
    return build_eth_frame(MAC_BROADCAST, smac, ETH_TYPE_ARP, arp)


def build_arp_reply(sender_mac, sender_ip, target_mac, target_ip):
    """Pack the matching reply to an ARP request."""
    smac = parse_mac(sender_mac) if isinstance(sender_mac, str) else sender_mac
    tmac = parse_mac(target_mac) if isinstance(target_mac, str) else target_mac
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HW_ETHER, ARP_PROTO_IPV4,
        6, 4, ARP_OP_REPLY,
        smac, ip_to_bytes4(sender_ip),
        tmac, ip_to_bytes4(target_ip),
    )
    return build_eth_frame(tmac, smac, ETH_TYPE_ARP, arp)


def parse_arp(payload):
    """Pull (op, sender_mac, sender_ip, target_mac, target_ip) from an
    ARP-payload (post-Ethernet).  Returns None for non-IPv4 ARP."""
    if len(payload) < 28:
        return None
    htype, ptype, hlen, plen, op, smac, sip, tmac, tip = struct.unpack(
        "!HHBBH6s4s6s4s", bytes(payload[:28]))
    if htype != ARP_HW_ETHER or ptype != ARP_PROTO_IPV4:
        return None
    if hlen != 6 or plen != 4:
        return None
    return (op, smac, sip, tmac, tip)


def ip_to_bytes4(addr):
    """'10.0.0.5' -> b'\\n\\x00\\x00\\x05'; pass-through for 4-byte input."""
    if isinstance(addr, (bytes, bytearray)) and len(addr) == 4:
        return bytes(addr)
    if not isinstance(addr, str):
        raise ValueError("ipv4 address must be string or 4 bytes")
    import socket
    return socket.inet_aton(addr)


def bytes4_to_ip(raw):
    """4-byte address -> dotted-quad string."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 4:
        raise ValueError("ipv4 address must be 4 bytes")
    import socket
    return socket.inet_ntoa(bytes(raw))


class ArpCache(object):
    """Tiny in-memory ARP table.  Entries time out after ttl_seconds.

    The TCP plugin populates this from sniffed ARP replies (and from
    gratuitous ARPs sent by peers) plus from the host's own kernel ARP
    table at startup (`/proc/net/arp` on Linux, `arp -an` elsewhere) so
    we don't have to issue a probe for every cold connect.
    """

    def __init__(self, ttl_seconds=300):
        self.ttl = ttl_seconds
        self.table = {}  # ip-string -> (mac_bytes, expiry_monotonic)

    def put(self, ip, mac):
        import time
        if isinstance(mac, str):
            mac = parse_mac(mac)
        if isinstance(ip, (bytes, bytearray)) and len(ip) == 4:
            ip = bytes4_to_ip(ip)
        self.table[ip] = (bytes(mac), time.monotonic() + self.ttl)

    def get(self, ip):
        import time
        if isinstance(ip, (bytes, bytearray)) and len(ip) == 4:
            ip = bytes4_to_ip(ip)
        entry = self.table.get(ip)
        if entry is None:
            return None
        mac, expiry = entry
        if time.monotonic() > expiry:
            del self.table[ip]
            return None
        return mac

    def feed_arp(self, payload):
        """Learn from a captured ARP packet (request or reply)."""
        parsed = parse_arp(payload)
        if parsed is None:
            return False
        op, smac, sip, tmac, tip = parsed
        if smac != MAC_ZERO and smac != MAC_BROADCAST:
            self.put(bytes4_to_ip(sip), smac)
        if op == ARP_OP_REPLY and tmac != MAC_ZERO and tmac != MAC_BROADCAST:
            self.put(bytes4_to_ip(tip), tmac)
        return True
