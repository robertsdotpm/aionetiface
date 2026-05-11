"""IP / Ethernet header pack-and-parse helpers.

Pure-protocol code -- importable on every platform.  No ctypes here;
the OS shims live in ../os/.

Modules:
    eth.py    -- Ethernet II framing + link-layer strip/wrap helpers
                 + tiny ARP cache for next-hop MAC lookup
    ipv4.py   -- RFC 791 IPv4 header pack/parse + RFC 1071 checksum
    ipv6.py   -- RFC 8200 IPv6 header pack/parse (skeleton; v6 punch later)
"""
from . import eth, ipv4, ipv6

__all__ = ("eth", "ipv4", "ipv6")
