"""STUN message types, attribute codes, and encoding helpers."""
from struct import pack
import hmac
import socket
import hashlib
from typing import Any, Optional, Tuple
from ...utility.utils import b_and, b_or, b_to_i, rand_b, xor_bufs
from ...net.net_defs import IP4, IP6

__all__ = [
    "STUN_CHANGE_NONE",
    "STUN_CHANGE_PORT",
    "STUN_CHANGE_BOTH",
    "STUN_MAGIC_COOKIE",
    "STUN_MAGIC_XOR",
    "RFC3489",
    "RFC5389",
    "RFC8489",
    "STUNMsgTypes",
    "STUNAttrs",
    "STUNMsgCodes",
    "STUNAddrTup",
    "STUNMsg",
]

STUN_CHANGE_NONE = 1
STUN_CHANGE_PORT = 2
STUN_CHANGE_BOTH = 3
STUN_MAGIC_COOKIE = b"\x21\x12\xa4\x42"
STUN_MAGIC_XOR = b"\x00\x00\x21\x12" + STUN_MAGIC_COOKIE
RFC3489 = 1
RFC5389 = 2
RFC8489 = 3


def _get_const_name(cls, val, type_: type) -> str:
    """Return the attribute name in cls whose value equals val and whose type matches type_, or an empty string."""
    for attr_name in dir(cls):
        attr = getattr(cls, attr_name)
        if isinstance(attr, type_) and attr == val:
            return attr_name
    return ""


class STUNMsgTypes:
    """STUN message type byte constants for all supported request and indication codes."""
    Reversed = b"\x00\x00"  # RFC5389
    Binding = b"\x00\x01"
    SharedSecret = b"\x00\x02"  # Reserved - RFC5389

    # https://tools.ietf.org/html/rfc5766#section-13
    # https://datatracker.ietf.org/doc/html/draft-rosenberg-midcom-turn-08#section-9.1
    Allocate = b"\x00\x03"
    Refresh = b"\x00\x04"
    Send = b"\x00\x06"  # 4 or 6? send was previously wrong
    SendResponse = b"\x01\x04"
    DataIndication = b"\x01\x15"
    Data = b"\x00\x07"
    CreatePermission = b"\x00\x08"
    ChannelBind = b"\x00\x09"

    # https://tools.ietf.org/html/rfc6062#section-6.1
    Connect = b"\x00\x0a"  # RFC6062
    ConnectionBind = b"\x00\x0b"  # RFC6062
    ConnectionAttempt = b"\x00\x0c"  # RFC6062

    get = classmethod(lambda cls, val, type_=int: _get_const_name(cls, val, type_))


class STUNAttrs:
    """STUN attribute type byte constants for all supported attribute codes."""
    Reserved = b"\x00\x00"  # RFC5389
    MappedAddress = b"\x00\x01"  # RFC5389
    ResponseAddress = b"\x00\x02"  # Reserved - RFC5389
    ChangeRequest = b"\x00\x03"  # Reserved - RFC5389
    SourceAddress = b"\x00\x04"  # Reserved - RFC5389
    ChangedAddress = b"\x00\x05"  # Reserved - RFC5389
    Username = b"\x00\x06"  # RFC5389
    Password = b"\x00\x07"  # Reserved - RFC5389
    MessageIntegrity = b"\x00\x08"  # RFC5389
    ErrorCode = b"\x00\x09"  # RFC5389
    UnknownAttribute = b"\x00\x0a"  # RFC5389
    ReflectedFrom = b"\x00\x0b"  # Reserved - RFC5389

    ChannelNumber = b"\x00\x0c"  # RFC5766
    Lifetime = b"\x00\x0d"  # RFC5766
    Bandwidth = b"\x00\x10"  # Reserved - RFC5766
    DestinationAddress = b"\x00\x11"

    XorPeerAddress = b"\x00\x12"  # RFC5766
    Data = b"\x00\x13"  # RFC5766

    Realm = b"\x00\x14"  # RFC5389
    Nonce = b"\x00\x15"  # RFC5389

    XorRelayedAddress = b"\x00\x16"  # RFC5766
    EvenPort = b"\x00\x18"  # RFC5766
    RequestedTransport = b"\x00\x19"  # RFC5766
    RequestedAddress = b"\x00\x17"  # draft-ietf-behave-turn-ipv6
    DontFragment = b"\x00\x1a"  # RFC5766

    XorMappedAddress = b"\x00\x20"  # RFC5389

    TimerVal = b"\x00\x21"  # Reserved - RFC5766
    ReservationToken = b"\x00\x22"  # RFC5766

    ConnectionID = b"\x00\x2a"  # RFC6062

    XorMappedAddressX = b"\x80\x20"
    Software = b"\x80\x22"  # RFC5389
    AlternateServer = b"\x80\x23"  # RFC5389
    Fingerprint = b"\x80\x28"  # RFC5389
    UnknownAddress2 = b"\x80\x2b"
    UnknownAddress3 = b"\x80\x2c"

    get = classmethod(lambda cls, val, type_=bytes: _get_const_name(cls, val, type_))


class STUNMsgCodes:
    """STUN message class byte constants distinguishing requests, indications, and responses."""
    Request = b"\x00\x00"
    Indication = b"\x00\x10"
    SuccessResp = b"\x01\x00"
    ErrorResp = b"\x01\x10"

    get = classmethod(lambda cls, val, type_=int: _get_const_name(cls, val, type_))


class STUNAddrTup:
    """Encode and decode STUN address attributes including XOR variants for IPv4 and IPv6."""
    def __init__(
        self,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        af: int = IP4,
        txid: bytes = b"",
        magic_cookie: bytes = STUN_MAGIC_XOR,
    ) -> None:
        self.ip = ip
        self.port = port
        self.af = af
        self.txid = txid
        self.magic_cookie = magic_cookie
        self.tup = ()

    def get_family_buf(self) -> bytes:
        """Return the two-byte STUN address family field for this instance's address family."""
        if self.af == IP4:
            return b"\0\1"
        else:
            return b"\0\2"

    @staticmethod
    def get_addr_bufs(af: int, attr_data: Any) -> Tuple[Any, Any]:
        """Return (ip_buf, port_buf) slices extracted from the raw attr_data bytes for the given address family.

        Note: `af` is a hint from the caller (typically the AF of the
        socket the message arrived on). It is NOT authoritative -- per
        RFC 5389 §15.1 every (XOR-)MAPPED-ADDRESS-style attribute carries
        its own one-byte family field at offset [1:2]. A TURN server
        connected to over IPv6 may legitimately return a v4 RELAYED-ADDRESS
        (or vice versa) so callers MUST honour the in-attribute family.
        See get_attr_family() / decode().
        """
        port_buf = attr_data[2:4]
        if af == IP4:
            ip_buf = attr_data[4:8]
        else:
            ip_buf = attr_data[4:20]

        return (ip_buf, port_buf)

    @staticmethod
    def get_attr_family(attr_data: Any) -> int:
        """Return the address family encoded inside the attribute itself
        (RFC 5389 §15.1: byte[1] is 0x01 for IPv4, 0x02 for IPv6).
        Falls back to IP4 on a malformed attribute. Use this in preference
        to the socket-level AF when decoding a (XOR-)MAPPED / PEER /
        RELAYED address, because TURN servers can hand back a relay in
        the OTHER family from the one used to reach them."""
        try:
            family_byte = bytes(attr_data[1:2])
        except Exception:
            return IP4
        if family_byte == b"\x02":
            return IP6
        return IP4

    @staticmethod
    def addr_bufs_to_tup(af: int, ip_buf: Any, port_buf: Any) -> Tuple[str, int]:
        """Convert raw IP and port byte buffers to a (ip_str, port_int) tuple."""
        port = b_to_i(port_buf, "big")
        ip = socket.inet_ntop(af, ip_buf)
        return (ip, port)

    def decode(self, code: Any, data: Any) -> Tuple[Any, Any, Any]:
        """Decode a STUN address attribute, un-XORing if required, and return (ip_buf, port_buf, processed_data).

        The address family used for slicing and inet_ntop is read from
        the attribute itself (data[1] = 0x01 for IPv4, 0x02 for IPv6)
        rather than from self.af. self.af is the AF of the socket the
        message arrived on -- TURN servers are free to hand back a v4
        relay over a v6 control connection (or vice versa) and the old
        code crashed with `ValueError: invalid length of packed IP
        address string` because get_addr_bufs(self.af=v6, 8-byte v4
        attr) tried to slice 16 IP bytes out of an 8-byte attr. Honour
        the wire family instead.
        """
        # Determine the in-attribute family BEFORE any XOR (the family
        # byte is at offset 1 of the unmasked attribute -- the leading
        # mask bytes are zeros so XORing it would be a no-op anyway,
        # but reading from the original is unambiguous).
        attr_af = STUNAddrTup.get_attr_family(data)

        # XORed per individual fields.
        if code == STUNAttrs.XorMappedAddressX:
            ip_buf, port_buf = STUNAddrTup.get_addr_bufs(attr_af, data)

            # UnXOR.
            mask = self.magic_cookie + self.txid
            port_buf = xor_bufs(port_buf, mask)
            ip_buf = xor_bufs(ip_buf, mask)
        else:
            ip_buf, port_buf = STUNAddrTup.get_addr_bufs(attr_af, data)

        # XORed starting from the port to the IP.
        codes = [
            STUNAttrs.XorMappedAddress,
            STUNAttrs.XorPeerAddress,
            STUNAttrs.XorRelayedAddress,
        ]
        if code in codes:
            mask = b"\x00\x00\x21\x12" + self.magic_cookie + self.txid
            if len(self.txid):
                data = xor_bufs(data, mask)

            # Re-extract from the un-XORed buffer using the wire family.
            ip_buf, port_buf = STUNAddrTup.get_addr_bufs(attr_af, data)

        # Convert to correct format using the wire family (NOT self.af).
        self.tup = STUNAddrTup.addr_bufs_to_tup(attr_af, ip_buf, port_buf)
        return ip_buf, port_buf, data

    def encode(self, code: Any) -> bytes:
        """Encode this instance's IP and port into a STUN address attribute byte buffer for the given attribute code."""
        # Convert IP address to binary.
        family = self.get_family_buf()
        if family == b"\0\1":
            ip_b = socket.inet_pton(socket.AF_INET, self.ip)
        else:
            ip_b = socket.inet_pton(socket.AF_INET6, self.ip)

        # Avoid copying fields as much as possible.
        buf = bytearray().join([family, memoryview(pack("!H", self.port)), ip_b])

        dec_ip, dec_port, dec_buf = self.decode(code, buf)

        # Decode moved to XOR across whole buffer so use that.
        if dec_buf != buf:
            return dec_buf
        return buf

    def pack(self, ip: str, port: int, af: int) -> bytes:
        """Create a new STUNAddrTup from ip, port, and af and return its encoded byte buffer."""
        inst = STUNAddrTup(
            ip=ip,
            port=port,
            af=af,
            xor_extra=self.xor_extra,
            magic_cookie=self.magic_cookie,
        )
        return inst.encode()

    def unpack(self, code: Any, data: Any) -> "STUNAddrTup":
        """Decode data into a new STUNAddrTup instance and return it."""
        inst = STUNAddrTup(af=self.af, txid=self.txid, magic_cookie=self.magic_cookie)
        inst.decode(code, data)
        return inst

    def __str__(self) -> str:
        return "{}:{}".format(self.ip, self.port)


class STUNMsg:
    """Build, pack, decode, and iterate over attributes of a STUN protocol message."""
    def __init__(
        self,
        msg_type: Any = STUNMsgTypes.Binding,
        msg_code: Any = STUNMsgCodes.Request,
        mode: int = RFC3489,
    ) -> None:
        self.msg_code = msg_code
        self.msg_type = msg_type  # type: int
        self.msg_len = 0  # type: int
        self.txn_id = rand_b(12)  # type: bytes
        self.msg = bytearray()
        self.attr_cursor = 0  # type: int
        self.mode = mode

        # To enable RFC 3489 compatibility the magic cookie is
        # intentionally set to an incorrect value.
        if self.mode == RFC3489:
            self.magic_cookie = b"1234"
        else:
            self.magic_cookie = STUN_MAGIC_COOKIE

    def reset_attr(self) -> None:
        """Clear all previously written attributes and reset the message length to zero."""
        self.msg_len = 0
        self.msg = bytearray()

    def write_attr(self, attr: bytes, *data, fmt: str = None) -> None:
        """Append a STUN attribute with the given code and data (optionally struct-formatted) to the message buffer."""
        # process data -> bytes
        if fmt:
            data = pack(fmt, *data)
        else:
            data = data[0]
            if isinstance(data, STUNAddrTup):
                data = data.encode(STUNAttrs.XorMappedAddress)

        # Rule of 4:
        # https://tools.ietf.org/html/rfc5766#section-14
        padding = b""
        if len(data) % 4 != 0:
            padding = b"\x00" * (4 - len(data) % 4)

        buf = bytearray().join(
            [
                memoryview(attr),
                memoryview(pack("!H", len(data))),
                memoryview(data),
                memoryview(padding),
            ]
        )

        self.msg_len += len(buf)
        self.msg += buf

    def write_credential(self, username: str, realm: str, nonce: bytes = b"") -> None:
        """Write Username, Realm, and Nonce attributes into the message for long-term credential authentication."""
        self.write_attr(STUNAttrs.Username, username)
        self.write_attr(STUNAttrs.Realm, realm)
        self.write_attr(STUNAttrs.Nonce, nonce)

    def _hmac(self, key: bytes, msg: bytes) -> bytes:
        """Return the HMAC-SHA1 digest of msg using key."""
        hashed = hmac.new(key, msg, hashlib.sha1)
        return hashed.digest()

    def write_hmac(self, key: bytes) -> None:
        """Compute and append a MessageIntegrity attribute using the HMAC-SHA1 of the current packed message."""
        self.msg_len += 24
        msg_hmac = self.pack()
        self.msg_len -= 24
        self.write_attr(STUNAttrs.MessageIntegrity, self._hmac(key, msg_hmac))

    def eof(self) -> bool:
        """Return True if the attribute cursor has reached the end of the message body."""
        return self.attr_cursor >= self.msg_len - 1

    def read_attr(self) -> tuple:
        """Read and return the next (attr_type, attr_len, attr_data) tuple from the message buffer."""
        # Process serialized attribute chunk using pointers.
        msg = memoryview(self.msg)
        msg_len = len(msg)
        m_attr = m_len = m_data = None
        if msg_len and self.attr_cursor + 3 <= msg_len - 1:
            # Unpack first two fields of an attribute.
            attr_hdr = msg[self.attr_cursor : self.attr_cursor + 4]
            m_attr = attr_hdr[0:2]
            m_len = b_to_i(attr_hdr[2:4], "big")

            # Avoid overflows for attribute data.
            self.attr_cursor += 4
            if m_len:
                if self.attr_cursor + (m_len - 1) <= msg_len - 1:
                    # Get attribute data.
                    m_data = msg[self.attr_cursor : self.attr_cursor + m_len]

                    # Rule of block 4:
                    # https://tools.ietf.org/html/rfc5766#section-14
                    attr_pad = 0
                    if m_len % 4 != 0:
                        attr_pad = 4 - m_len % 4

                    # Increase attribute pointer.
                    self.attr_cursor += m_len + attr_pad
                else:
                    raise Exception("TURN attribute len invalid.")

        # Return results.
        return m_attr, m_len, m_data

    def __bytes__(self) -> bytes:
        return b""

    def pack(self) -> bytes:
        """Serialise the message header and all written attributes into a complete STUN wire-format byte string."""
        # Starting with RFC 5389 and on a more complex
        # bit scheme is used for the message type.
        if self.mode != RFC3489:
            msg_type = b_and(b_or(self.msg_type, self.msg_code), b"\x3f\xff")
        else:
            msg_type = self.msg_type

        return bytes().join(
            [
                msg_type,
                pack("!H", self.msg_len),
                self.magic_cookie,
                self.txn_id,
                self.msg,
            ]
        )

    def decode(self, msg: Any) -> Optional[Any]:
        """Populate this instance's fields from a raw STUN byte buffer and return any trailing bytes."""
        # Unpack data from buffer using memory views.
        msg_len = len(msg)
        self.attr_cursor = 0
        if msg_len >= 20:
            # Unpack message fields.
            self.msg_type = msg[0:2]
            self.msg_len = b_to_i(msg[2:4], "big")
            self.magic_cookie = msg[4:8]
            self.txn_id = msg[8:20]

            # Make sure message len accurately reflects size.
            if self.msg_len:
                if 20 + (self.msg_len - 1) <= msg_len - 1:
                    self.msg = msg[20 : 20 + self.msg_len]

                    # ret data left in buffer, usually NULL
                    return msg[20 + self.msg_len :]
                else:
                    raise Exception("Invalid length for STUN msg.")

    def unpack(msg: Any, mode: int = RFC3489) -> Tuple["STUNMsg", Any]:
        """Decode msg into a new STUNMsg instance and return (instance, trailing_bytes)."""
        inst = STUNMsg(mode=mode)
        buf = inst.decode(msg)
        return inst, buf
