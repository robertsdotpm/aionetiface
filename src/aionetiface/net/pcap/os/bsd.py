"""BSD libpcap shim.

FreeBSD ships libpcap in base (/usr/lib/libpcap.so) -- so does
OpenBSD and NetBSD.  No pkg install needed for FreeBSD; the test
environment notes mention `pkg install` only for libpcap *headers*
which we don't need here (we bind the ABI from ctypes, not the
build-time API).

DLT note: BSD loopback interfaces (lo0) use DLT_NULL (0) with a
4-byte AF_* prefix instead of the Ethernet header that Linux's "lo"
uses (DLT_EN10MB with the all-zero MACs).  The userspace TCP layer
in tcp/ has to branch on backend.datalink() for that reason.

References:
  - pcap-savefile(5) for the DLT_NULL framing details:
    https://www.tcpdump.org/manpages/pcap-savefile.5.html
"""
import ctypes

from .libpcap_core import LibpcapFactory, bind_symbols


BSD_LIBPCAP_CANDIDATES = (
    "libpcap.so",
    "libpcap.so.1",
    "/usr/lib/libpcap.so",
    "/usr/local/lib/libpcap.so",
)


class BsdFactory(LibpcapFactory):
    platform_name = "bsd/libpcap"

    def load_lib(self):
        last_err = None
        for candidate in BSD_LIBPCAP_CANDIDATES:
            try:
                lib = ctypes.CDLL(candidate, use_errno=True)
                bind_symbols(lib)
                self.library_path_label = candidate
                print("pcap/bsd: loaded {0}".format(candidate))
                return lib
            except OSError as exc:
                last_err = exc
                continue
        if last_err is not None:
            print("pcap/bsd: no libpcap candidate loaded; last error: {0}".format(last_err))
        return None


factory = BsdFactory()
