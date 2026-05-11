"""Windows WinPcap / Npcap shim.

Both WinPcap 4.1.3 (the last version that supports Windows XP) and
Npcap (the modern fork, default install path
C:\\Windows\\System32\\Npcap) expose libpcap's C ABI via wpcap.dll.
We try to load it from the standard install locations.

Library load search order:
  1. ``wpcap.dll`` -- if the loader's PATH already covers it
     (Npcap default install puts wpcap.dll under
     C:\\Windows\\System32\\Npcap which is NOT on PATH unless the
     installer was run with the "Install Npcap in WinPcap API-
     compatible Mode" checkbox + the legacy redirector).
  2. ``C:\\Windows\\System32\\Npcap\\wpcap.dll`` -- explicit Npcap path.
  3. ``C:\\Windows\\System32\\wpcap.dll`` -- WinPcap 4.1.3's install
     path (the one we care about on Windows XP).
  4. ``C:\\Windows\\SysWOW64\\wpcap.dll`` -- 32-bit DLL view on 64-bit
     hosts; used when running 32-bit Python on a 64-bit host (the
     XP test VM is 32-bit so this branch is for the modern Windows
     dev hosts only).

Interface naming:
  - On Windows, pcap interface names look like
    ``\\Device\\NPF_{GUID}``.  Users almost never want to type those;
    list_interfaces() returns the friendly description alongside the
    NPF name so callers can match on either.

NDIS / driver gotchas (per WinPcap docs and our own XP testing):
  - WinPcap 4.1.3 needs the "NPF" service running to capture or
    inject.  The installer registers it as auto-start.  If the
    service is stopped, pcap_open_live returns NULL with errbuf
    "Error opening adapter: The system cannot find the file
    specified. (3)".
  - On Vista+ (Npcap), the NPF service is renamed "npcap" and
    requires administrator launch unless installed in WinPcap-
    compat mode.
  - WinPcap on XP does NOT need administrator -- once NPF is
    installed and running, any user can open and inject.

References:
  - WinPcap docs: https://www.winpcap.org/docs/docs_412/html/main.html
  - Npcap users' guide: https://npcap.com/guide/npcap-users-guide.html
  - WinPcap install / NPF service:
    https://www.winpcap.org/docs/docs_412/html/group__remote__pri__src.html
"""
import ctypes
import os

from .libpcap_core import LibpcapFactory, bind_symbols


WINDOWS_WPCAP_CANDIDATES = (
    "wpcap.dll",
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
    r"C:\Windows\System32\wpcap.dll",
    r"C:\Windows\SysWOW64\wpcap.dll",
)


class WindowsFactory(LibpcapFactory):
    platform_name = "windows/wpcap"

    def load_lib(self):
        # Npcap-in-WinPcap-compat mode often installs a stub wpcap.dll
        # that needs Packet.dll on the same path -- so we tell Windows
        # to search both via SetDllDirectoryW when an Npcap folder is
        # picked.  Best-effort: failure here just means the bare
        # ctypes.WinDLL call has to find its dependencies on its own.
        last_err = None
        for candidate in WINDOWS_WPCAP_CANDIDATES:
            try:
                # If we have a full path, hint the DLL loader at the
                # parent folder so Packet.dll resolves alongside.
                parent = ""
                if os.sep in candidate or "/" in candidate:
                    parent = os.path.dirname(candidate)
                    if parent:
                        try:
                            kernel32 = ctypes.WinDLL("kernel32")
                            kernel32.SetDllDirectoryW(ctypes.c_wchar_p(parent))
                        except OSError:
                            pass
                lib = ctypes.WinDLL(candidate, use_errno=True)
                bind_symbols(lib)
                self.library_path_label = candidate
                print("pcap/windows: loaded {0}".format(candidate))
                return lib
            except OSError as exc:
                last_err = exc
                continue
        if last_err is not None:
            print("pcap/windows: no wpcap.dll candidate loaded; last error: {0}".format(last_err))
        return None


factory = WindowsFactory()
