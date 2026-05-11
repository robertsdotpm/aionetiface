"""Platform-specific pcap shims.

Each module in this package binds the libpcap ABI for one OS family
via ctypes and exports a module-level `factory` (BackendFactory
instance).  The top-level `backend.get_backend()` picks the right one
based on sys.platform.

Why ctypes-direct and not pcapy / pylibpcap / scapy:
  - pcapy is a C extension and ships no wheel for Py3.5 / Windows XP.
  - pylibpcap is similarly out-of-date and abandoned upstream.
  - scapy is far heavier than the four-or-five libpcap symbols we
    actually need and pulls in optional crypto deps.
  - The libpcap C ABI has been stable since libpcap 0.9 (~2005),
    which covers every system in our test matrix.

References:
  - libpcap manpages live at https://www.tcpdump.org/manpages/
  - WinPcap developer pack docs:
    https://www.winpcap.org/docs/docs_412/html/group__wpcap.html
  - Npcap is API-compatible with WinPcap by design:
    https://npcap.com/guide/wpcap/intro.html
"""
