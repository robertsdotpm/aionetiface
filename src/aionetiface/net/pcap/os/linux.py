"""Linux libpcap shim.

Loads libpcap.so via the standard search order:
  1. libpcap.so.1   -- libpcap 1.x soname on every modern distro
  2. libpcap.so.0.8 -- legacy soname still shipped by older Debian/RHEL
  3. libpcap.so     -- the unversioned developer symlink

We try them in that order via ctypes.CDLL.  Note we do NOT use
ctypes.util.find_library("pcap") -- that calls out to ldconfig in
the most useful way on glibc but on musl / Alpine returns None even
when libpcap is installed.  Direct dlopen is more reliable.

Permissions:
  - Opening a non-loopback interface requires CAP_NET_RAW (or root)
    in the calling process.  Loopback ("lo") + the per-userns network
    namespace are the only exceptions.
  - For tcp_punch the calling process must already have CAP_NET_RAW
    or we degrade to legacy tcp_punch -- the BackendFactory exposes
    that via available() returning True before open() raises, so the
    warpgate plugin can check up front.

References:
  - libpcap on Linux: https://www.tcpdump.org/manpages/pcap.3pcap.html
  - capabilities(7) for CAP_NET_RAW semantics:
    https://man7.org/linux/man-pages/man7/capabilities.7.html
"""
import ctypes

from .libpcap_core import LibpcapFactory


LINUX_LIBPCAP_CANDIDATES = (
    "libpcap.so.1",
    "libpcap.so.0.8",
    "libpcap.so.0",
    "libpcap.so",
)


class LinuxFactory(LibpcapFactory):
    platform_name = "linux/libpcap"

    def load_lib(self):
        last_err = None
        for candidate in LINUX_LIBPCAP_CANDIDATES:
            try:
                from .libpcap_core import bind_symbols
                lib = ctypes.CDLL(candidate, use_errno=True)
                bind_symbols(lib)
                self.library_path_label = candidate
                return lib
            except OSError as exc:
                last_err = exc
                continue
        if last_err is not None:
            pass
        return None


factory = LinuxFactory()
