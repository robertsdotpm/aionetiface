"""macOS libpcap shim.

macOS ships libpcap as part of the OS at /usr/lib/libpcap.A.dylib with
a stable libpcap.dylib symlink.  The Apple-shipped version is
typically a few minor versions behind the libpcap upstream but the
symbol surface we use has been stable since 0.9.

Note: starting with macOS Big Sur (11) Apple stopped exposing the
system dylibs on the filesystem; ctypes.CDLL still resolves them via
the dyld shared cache, so the bare "libpcap.dylib" name works even
when `ls /usr/lib/libpcap.dylib` shows nothing.

References:
  - https://developer.apple.com/documentation/macos-release-notes/macos-big-sur-11_0_1-release-notes
    (note about dyld shared cache and missing on-disk libraries)
"""
import ctypes

from .libpcap_core import LibpcapFactory, bind_symbols


DARWIN_LIBPCAP_CANDIDATES = (
    "libpcap.dylib",
    "/usr/lib/libpcap.dylib",
    "/usr/lib/libpcap.A.dylib",
)


class DarwinFactory(LibpcapFactory):
    platform_name = "darwin/libpcap"

    def load_lib(self):
        last_err = None
        for candidate in DARWIN_LIBPCAP_CANDIDATES:
            try:
                lib = ctypes.CDLL(candidate, use_errno=True)
                bind_symbols(lib)
                self.library_path_label = candidate
                print("pcap/darwin: loaded {0}".format(candidate))
                return lib
            except OSError as exc:
                last_err = exc
                continue
        if last_err is not None:
            print("pcap/darwin: no libpcap candidate loaded; last error: {0}".format(last_err))
        return None


factory = DarwinFactory()
