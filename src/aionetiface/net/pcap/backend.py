"""Abstract pcap Backend + capability detection.

The Backend ABC defines the *minimum* primitive set every platform
shim must implement.  Everything higher up (userspace TCP, the
Pipe-shaped wrappers in loopback.py, the p2pd plugin) is written to
this interface so the platform shims can stay tiny.

References:
  - libpcap manpage (pcap(3PCAP)) for the function naming + semantics
    we mirror: pcap_open_live, pcap_sendpacket, pcap_next_ex,
    pcap_compile/pcap_setfilter, pcap_close, pcap_findalldevs.
    https://www.tcpdump.org/manpages/pcap.3pcap.html
  - WinPcap maintains the same surface; the Npcap fork on modern
    Windows is API-compatible with WinPcap 4.1.3 by design.
    https://npcap.com/guide/wpcap/intro.html

Design notes:

- This file holds no ctypes.  ctypes lives in os/<platform>.py so a
  failure to find libpcap on one machine does not poison every other
  import path in aionetiface.

- get_backend() is the only public entry point that loads native
  code.  It picks the right shim based on sys.platform and raises
  PcapUnavailableError on hosts where loading the shared library
  fails.  Callers are expected to handle that exception cleanly
  (the p2pd plugin uses it to fall back to legacy tcp_punch when
  pcap is missing, and the unit tests use it to skipTest).

- We are deliberately not using pcapy / pylibpcap / scapy.  Those
  ship native extensions that do not always build on Python 3.5 /
  Windows XP, and they are larger than the surface we actually need.
  ctypes-direct keeps the dependency footprint at "libpcap is on
  the box" which is what we already need.
"""
import sys


class PcapError(Exception):
    """Generic pcap-layer error -- raised once a backend is open and
    a libpcap call fails.  Carries the libpcap errbuf when available."""


class PcapUnavailableError(PcapError):
    """Raised when the platform shim cannot be loaded at all -- e.g.
    wpcap.dll is not installed on Windows, or libpcap.so could not
    be located on Linux.  Callers (the p2pd plugin) treat this as
    "pcap mode disabled" and fall back to the legacy path."""


class Backend(object):
    """Minimum pcap primitive set.

    A Backend instance is bound to one capture handle (one pcap_t in
    libpcap terms).  Open one per interface you want to read or
    inject frames on.

    Lifecycle:
        b = backend_factory.open("eth0", snaplen=65535, promisc=False, timeout_ms=10)
        b.set_filter("tcp and host 10.0.0.1")
        while True:
            frame = b.recv(timeout_ms=100)
            if frame is None:
                continue
            ...
        b.send(my_frame_bytes)
        b.close()

    Backends are NOT thread-safe.  One asyncio task per backend, or
    explicit locking by the caller.
    """

    # Populated by the os/ shim that produced this instance, so callers
    # (and the unit tests) can sanity-check what they got.
    platform_name = "abstract"

    def send(self, frame_bytes):
        """Inject a raw Ethernet frame onto the wire.  Caller owns the
        Ethernet + IP + L4 headers; the backend writes the bytes through
        unchanged.  Returns the number of bytes written."""
        raise NotImplementedError

    def recv(self, timeout_ms=100):
        """Return the next captured frame as bytes, or None on timeout.
        Honours any BPF filter set with set_filter().  Blocks at most
        timeout_ms in real time -- shorter values give the asyncio loop
        room to schedule other tasks between calls."""
        raise NotImplementedError

    def set_filter(self, bpf_string):
        """Compile + install a BPF filter on this handle.  Empty string
        clears the filter.  Filters massively reduce the amount of
        frames the userspace TCP layer has to look at on a busy
        loopback / LAN."""
        raise NotImplementedError

    def datalink(self):
        """Return the DLT_* integer for this handle.  We mainly care
        about DLT_EN10MB (Ethernet, 1) vs DLT_NULL (BSD loopback, 0)
        vs DLT_RAW (12) because the header-stripping math differs."""
        raise NotImplementedError

    def close(self):
        """Tear down the capture handle.  Idempotent."""
        raise NotImplementedError


class BackendFactory(object):
    """Per-platform entry point.  Each os/ shim exports an instance.

    Kept separate from Backend so list_interfaces() and version
    detection can run before (or without) an actual capture is opened.
    """

    platform_name = "abstract"

    def available(self):
        """True if the underlying shared library loaded cleanly.  False
        means open()/list_interfaces() will raise PcapUnavailableError."""
        raise NotImplementedError

    def library_version(self):
        """Free-form pcap-lib version string (libpcap N.N / WinPcap
        4.1.3 / Npcap X.Y).  For logging only; the protocol code does
        not branch on it."""
        raise NotImplementedError

    def list_interfaces(self):
        """Return a list of dicts:
            [{"name": "eth0", "description": "...", "loopback": False,
              "addresses": ["10.0.0.5", "fe80::..."]},
             ...]
        Mirrors pcap_findalldevs but flattens to plain Python data."""
        raise NotImplementedError

    def open(self, iface_name, snaplen=65535, promisc=False, timeout_ms=10):
        """Open a capture+inject handle on iface_name.  Returns a
        Backend instance.  Raises PcapError if the handle cannot be
        opened (wrong name, permission denied, driver not loaded)."""
        raise NotImplementedError


def list_backends():
    """Return the ordered list of (platform_key, factory_module_name)
    candidates we know about, regardless of whether any are installed.
    Mostly useful for diagnostics in tests."""
    return (
        ("win32", "aionetiface.net.pcap.os.windows"),
        ("cygwin", "aionetiface.net.pcap.os.windows"),
        ("linux", "aionetiface.net.pcap.os.linux"),
        ("linux2", "aionetiface.net.pcap.os.linux"),
        ("darwin", "aionetiface.net.pcap.os.darwin"),
        ("freebsd", "aionetiface.net.pcap.os.bsd"),
        ("openbsd", "aionetiface.net.pcap.os.bsd"),
        ("netbsd", "aionetiface.net.pcap.os.bsd"),
    )


def pick_module_name(platform=None):
    """Internal: map sys.platform to the shim import path.  Exposed
    as a function so the unit tests can drive it without monkey-
    patching sys.platform."""
    if platform is None:
        platform = sys.platform
    for key, mod in list_backends():
        if platform == key or platform.startswith(key):
            return mod
    raise PcapUnavailableError(
        "no pcap backend mapped for sys.platform={0}".format(platform)
    )


def get_backend(platform=None):
    """Return the BackendFactory for the current platform (or `platform`
    if given).  Raises PcapUnavailableError if the platform isn't
    mapped or the native library cannot be loaded.

    This is the lazy-load chokepoint -- import this module on any host
    without touching ctypes, then call get_backend() only when you
    actually intend to use pcap."""
    mod_name = pick_module_name(platform)
    try:
        import importlib
        mod = importlib.import_module(mod_name)
    except ImportError as exc:
        raise PcapUnavailableError(
            "could not import pcap shim {0}: {1}".format(mod_name, exc)
        )
    factory = getattr(mod, "factory", None)
    if factory is None:
        raise PcapUnavailableError(
            "pcap shim {0} has no factory attribute".format(mod_name)
        )
    if not factory.available():
        raise PcapUnavailableError(
            "pcap shim {0} loaded but underlying library unavailable".format(mod_name)
        )
    return factory
