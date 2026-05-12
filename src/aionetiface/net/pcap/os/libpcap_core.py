"""Shared libpcap ctypes binding.

Every Unix shim (linux.py, bsd.py, darwin.py) and the Windows shim
(windows.py) call into this module after locating the right shared
library / DLL.  The libpcap C ABI has been stable since libpcap 0.9
(2005) -- WinPcap 4.1.3 is libpcap 1.0-era, Npcap is libpcap 1.10-era,
modern Linux ships libpcap 1.x -- and the symbol surface we need has
not changed:

    pcap_findalldevs / pcap_freealldevs
    pcap_open_live
    pcap_close
    pcap_sendpacket
    pcap_next_ex
    pcap_compile / pcap_setfilter / pcap_freecode
    pcap_datalink
    pcap_lib_version
    pcap_geterr

That is all the userspace TCP layer needs.  Everything else (filter
optimisation, statistics, asynchronous capture loops) we either don't
care about or rebuild in pure Python.

References:
  - pcap(3PCAP)  https://www.tcpdump.org/manpages/pcap.3pcap.html
  - pcap_next_ex(3PCAP)  https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html
  - pcap_sendpacket(3PCAP)  https://www.tcpdump.org/manpages/pcap_sendpacket.3pcap.html
  - pcap_findalldevs(3PCAP)  https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
"""
import ctypes
from ctypes import (
    POINTER, Structure, c_char, c_char_p, c_int, c_uint, c_uint32,
    c_void_p, c_short, c_ushort, c_ubyte, byref, cast, create_string_buffer,
)
import socket as stdlib_socket

from ..backend import Backend, BackendFactory, PcapError, PcapUnavailableError


PCAP_ERRBUF_SIZE = 256

# Common DLT (data link type) values.  See:
# https://www.tcpdump.org/linktypes.html
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12   # on most platforms (BSD/Linux); see linktypes.html
DLT_LOOP = 108  # OpenBSD loopback

# pcap_next_ex return codes
PCAP_NEXT_OK = 1
PCAP_NEXT_TIMEOUT = 0
PCAP_NEXT_EOF = -2
PCAP_NEXT_ERROR = -1


class TimevalT(Structure):
    """Mirror of struct timeval as libpcap consumes it.  Field widths
    are platform-specific (32-bit vs 64-bit time_t) but for our use
    -- we only read it for ordering, never write it -- c_long is fine
    on every libpcap target we have.  The struct is opaque to us if
    we don't read those fields, so this is a defensive shape only."""
    _fields_ = (
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_long),
    )


class PcapPktHdr(Structure):
    """Mirror of struct pcap_pkthdr -- the header libpcap prepends to
    each captured frame.  caplen is what's actually in the buffer
    (snaplen-bounded), len is the original on-wire length."""
    _fields_ = (
        ("ts", TimevalT),
        ("caplen", c_uint32),
        ("len", c_uint32),
    )


class BpfProgram(Structure):
    """struct bpf_program -- output of pcap_compile, input to
    pcap_setfilter.  We treat the contents as opaque and only pass
    pointers around."""
    _fields_ = (
        ("bf_len", c_uint),
        ("bf_insns", c_void_p),
    )


class SockaddrIn(Structure):
    """Just enough of struct sockaddr_in to pull the IPv4 address out
    of a pcap_addr.addr pointer when listing interfaces."""
    _fields_ = (
        ("sin_family", c_ushort),
        ("sin_port", c_ushort),
        ("sin_addr", c_uint32),
        ("sin_zero", c_char * 8),
    )


class SockaddrIn6(Structure):
    """Just enough of struct sockaddr_in6 for IPv6 address extraction
    out of pcap_addr.addr."""
    _fields_ = (
        ("sin6_family", c_ushort),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", c_ubyte * 16),
        ("sin6_scope_id", c_uint32),
    )


class PcapAddr(Structure):
    pass


# Self-referential next pointer -- declared after the class body.
PcapAddr._fields_ = (
    ("next", POINTER(PcapAddr)),
    ("addr", c_void_p),
    ("netmask", c_void_p),
    ("broadaddr", c_void_p),
    ("dstaddr", c_void_p),
)


class PcapIf(Structure):
    pass


PcapIf._fields_ = (
    ("next", POINTER(PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(PcapAddr)),
    ("flags", c_uint32),
)


PCAP_IF_LOOPBACK = 0x00000001
PCAP_IF_UP = 0x00000002


def bind_symbols(lib):
    """Attach argtypes / restype to every pcap_* symbol we touch.

    Done once per shim, after the shim has located its shared library.
    Returns the same lib so callers can chain or store it directly.
    """
    lib.pcap_lib_version.argtypes = ()
    lib.pcap_lib_version.restype = c_char_p

    lib.pcap_findalldevs.argtypes = (POINTER(POINTER(PcapIf)), c_char_p)
    lib.pcap_findalldevs.restype = c_int

    lib.pcap_freealldevs.argtypes = (POINTER(PcapIf),)
    lib.pcap_freealldevs.restype = None

    lib.pcap_open_live.argtypes = (c_char_p, c_int, c_int, c_int, c_char_p)
    lib.pcap_open_live.restype = c_void_p

    lib.pcap_close.argtypes = (c_void_p,)
    lib.pcap_close.restype = None

    lib.pcap_sendpacket.argtypes = (c_void_p, c_char_p, c_int)
    lib.pcap_sendpacket.restype = c_int

    lib.pcap_next_ex.argtypes = (
        c_void_p, POINTER(POINTER(PcapPktHdr)), POINTER(POINTER(c_ubyte))
    )
    lib.pcap_next_ex.restype = c_int

    lib.pcap_compile.argtypes = (
        c_void_p, POINTER(BpfProgram), c_char_p, c_int, c_uint32
    )
    lib.pcap_compile.restype = c_int

    lib.pcap_setfilter.argtypes = (c_void_p, POINTER(BpfProgram))
    lib.pcap_setfilter.restype = c_int

    lib.pcap_freecode.argtypes = (POINTER(BpfProgram),)
    lib.pcap_freecode.restype = None

    lib.pcap_datalink.argtypes = (c_void_p,)
    lib.pcap_datalink.restype = c_int

    lib.pcap_geterr.argtypes = (c_void_p,)
    lib.pcap_geterr.restype = c_char_p

    return lib


def decode_sockaddr(addr_ptr):
    """Read a sockaddr_in / sockaddr_in6 out of a void* and return the
    string-form address, or None on unknown family / null pointer."""
    if not addr_ptr:
        return None
    # The leading sa_family field is at offset 0 for both BSD-derived
    # and Linux sockaddr layouts (Linux uses a 16-bit sa_family; BSD
    # uses 8-bit sa_len + 8-bit sa_family which lands the family byte
    # at offset 1).  Trying both gives us cross-platform interface
    # listing without per-OS branches here.
    family_word = ctypes.cast(addr_ptr, POINTER(c_ushort))[0]
    family_low = family_word & 0xff
    family_high = (family_word >> 8) & 0xff
    candidates = (family_low, family_high, family_word)
    for fam in candidates:
        if fam == stdlib_socket.AF_INET:
            sa = ctypes.cast(addr_ptr, POINTER(SockaddrIn))[0]
            # sin_addr.s_addr is stored in network byte order in the
            # kernel struct.  ctypes' c_uint32 reads it as a host-
            # endian integer, so pack with native ("=") byte order to
            # recover the original in-memory layout.
            import struct
            packed = struct.pack("=I", int(sa.sin_addr) & 0xffffffff)
            try:
                return stdlib_socket.inet_ntop(stdlib_socket.AF_INET, packed)
            except (OSError, ValueError):
                return None
        if fam == stdlib_socket.AF_INET6:
            sa = ctypes.cast(addr_ptr, POINTER(SockaddrIn6))[0]
            packed = bytes(bytearray(sa.sin6_addr))
            try:
                return stdlib_socket.inet_ntop(stdlib_socket.AF_INET6, packed)
            except (OSError, ValueError):
                return None
    return None


class LibpcapBackend(Backend):
    """Backend instance wrapping one pcap_t handle.

    Concrete shims share this class and only differ in how they
    located libpcap.  `lib` is the bound ctypes.CDLL; `handle` is the
    pcap_t pointer returned by pcap_open_live.
    """

    def __init__(self, lib, handle, iface_name, datalink_value):
        self.lib = lib
        self.handle = handle
        self.iface_name = iface_name
        self.datalink_value = datalink_value
        self.closed = False
        self.platform_name = "libpcap"

    def datalink(self):
        return self.datalink_value

    def send(self, frame_bytes):
        if self.closed:
            raise PcapError("send on closed pcap handle")
        if not isinstance(frame_bytes, (bytes, bytearray)):
            raise ValueError("frame_bytes must be bytes or bytearray")
        buf = bytes(frame_bytes)
        rc = self.lib.pcap_sendpacket(self.handle, buf, len(buf))
        if rc != 0:
            err = self.lib.pcap_geterr(self.handle)
            err_text = err.decode("ascii", "replace") if err else "unknown"
            raise PcapError("pcap_sendpacket failed: {0}".format(err_text))
        return len(buf)

    def recv(self, timeout_ms=100):
        """Wraps pcap_next_ex.  Returns bytes or None on timeout.

        timeout_ms is largely advisory -- libpcap's per-call timeout is
        the one set at pcap_open_live time.  We loop briefly inside so
        a caller-provided shorter window still feels responsive even
        when the underlying read-timeout is 10 ms (our default for
        open_live)."""
        if self.closed:
            raise PcapError("recv on closed pcap handle")
        hdr_ptr = POINTER(PcapPktHdr)()
        data_ptr = POINTER(c_ubyte)()
        rc = self.lib.pcap_next_ex(self.handle, byref(hdr_ptr), byref(data_ptr))
        if rc == PCAP_NEXT_OK:
            caplen = hdr_ptr[0].caplen
            if caplen == 0:
                return b""
            return ctypes.string_at(data_ptr, caplen)
        if rc == PCAP_NEXT_TIMEOUT:
            return None
        if rc == PCAP_NEXT_EOF:
            raise PcapError("pcap_next_ex: end of capture (savefile EOF)")
        # rc == -1 or unknown
        err = self.lib.pcap_geterr(self.handle)
        err_text = err.decode("ascii", "replace") if err else "unknown"
        raise PcapError("pcap_next_ex failed: {0}".format(err_text))

    def set_filter(self, bpf_string):
        if self.closed:
            raise PcapError("set_filter on closed pcap handle")
        prog = BpfProgram()
        text = bpf_string.encode("ascii") if bpf_string else b""
        # netmask=0 is acceptable when we are not filtering by network
        # mask (pcap docs say PCAP_NETMASK_UNKNOWN is fine for live).
        rc = self.lib.pcap_compile(self.handle, byref(prog), text, 1, 0)
        if rc != 0:
            err = self.lib.pcap_geterr(self.handle)
            err_text = err.decode("ascii", "replace") if err else "unknown"
            raise PcapError("pcap_compile({0!r}) failed: {1}".format(
                bpf_string, err_text))
        try:
            rc = self.lib.pcap_setfilter(self.handle, byref(prog))
            if rc != 0:
                err = self.lib.pcap_geterr(self.handle)
                err_text = err.decode("ascii", "replace") if err else "unknown"
                raise PcapError("pcap_setfilter failed: {0}".format(err_text))
        finally:
            self.lib.pcap_freecode(byref(prog))

    def close(self):
        if self.closed:
            return
        try:
            self.lib.pcap_close(self.handle)
        finally:
            self.closed = True
            self.handle = None


class LibpcapFactory(BackendFactory):
    """Shared factory base used by every Unix shim and by Windows
    once it's loaded wpcap.dll.  Concrete subclasses override the
    `load_lib()` hook to return either the bound CDLL or None."""

    platform_name = "libpcap"
    library_path_label = "libpcap"

    def __init__(self):
        self.lib = None
        self.load_attempted = False

    def load_lib(self):
        """Return a bound CDLL or None.  Subclasses do platform-specific
        discovery here -- we never try to second-guess where libpcap
        lives on disk from inside this base class."""
        return None

    def ensure_loaded(self):
        if self.load_attempted:
            return self.lib is not None
        self.load_attempted = True
        try:
            self.lib = self.load_lib()
        except OSError as exc:
            self.lib = None
        return self.lib is not None

    def available(self):
        return self.ensure_loaded()

    def library_version(self):
        if not self.ensure_loaded():
            return None
        ver = self.lib.pcap_lib_version()
        if ver is None:
            return None
        return ver.decode("ascii", "replace")

    def list_interfaces(self):
        if not self.ensure_loaded():
            raise PcapUnavailableError("pcap library not loaded")
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        head_ptr = POINTER(PcapIf)()
        rc = self.lib.pcap_findalldevs(byref(head_ptr), errbuf)
        if rc != 0:
            raise PcapError("pcap_findalldevs failed: {0}".format(
                errbuf.value.decode("ascii", "replace")))
        out = []
        try:
            cur = head_ptr
            while cur:
                node = cur[0]
                addrs = []
                acur = node.addresses
                while acur:
                    a = acur[0]
                    val = decode_sockaddr(a.addr)
                    if val:
                        addrs.append(val)
                    acur = a.next
                name = node.name.decode("ascii", "replace") if node.name else ""
                desc = (node.description.decode("ascii", "replace")
                        if node.description else "")
                out.append({
                    "name": name,
                    "description": desc,
                    "loopback": bool(node.flags & PCAP_IF_LOOPBACK),
                    "up": bool(node.flags & PCAP_IF_UP),
                    "addresses": addrs,
                })
                cur = node.next
        finally:
            self.lib.pcap_freealldevs(head_ptr)
        return out

    def open(self, iface_name, snaplen=65535, promisc=False, timeout_ms=10):
        if not self.ensure_loaded():
            raise PcapUnavailableError("pcap library not loaded")
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        name_bytes = iface_name.encode("utf-8") if isinstance(iface_name, str) else iface_name
        handle = self.lib.pcap_open_live(
            name_bytes,
            int(snaplen),
            1 if promisc else 0,
            int(timeout_ms),
            errbuf,
        )
        if not handle:
            raise PcapError("pcap_open_live({0!r}) failed: {1}".format(
                iface_name, errbuf.value.decode("ascii", "replace")))
        dlt = self.lib.pcap_datalink(handle)
        return LibpcapBackend(self.lib, handle, iface_name, dlt)
