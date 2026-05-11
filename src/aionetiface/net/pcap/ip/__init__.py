"""IP / Ethernet header pack-and-parse -- populated in Phase 2.

Phase 1 only ships the OS pcap shims.  The Phase-2 work will add:
    eth.py    -- Ethernet II framing (DLT_EN10MB)
    ipv4.py   -- RFC 791 IPv4 header pack/parse + checksum
    ipv6.py   -- RFC 8200 IPv6 header pack/parse
"""
