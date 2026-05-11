"""Userspace pcap-based networking primitives.

This module exposes a thin, portable layer over libpcap / WinPcap /
Npcap so the rest of aionetiface (and downstream p2pd plugins) can
ship and receive raw Ethernet frames from user space.

The immediate driver for adding it is Windows XP cross-NAT
tcp_punch -- XP's in-kernel TCP/IP stack (tcpip.sys) RSTs simul-open
handshakes 140-180 ms after they complete, which can only be worked
around by talking to the wire below tcpip.sys.  See
/home/x/projects/p2pd/CLAUDE.md "Windows XP cross-NAT tcp_punch is
not fixable from user-space (tcpip.sys simul-open RST)" for the
background.

Layout:
  backend.py    -- abstract Backend class every OS shim implements
  loopback.py   -- Pipe-shaped wrappers used by p2pd plugins
  os/           -- ctypes-level bindings (one module per platform)
  tcp/          -- pure-protocol userspace TCP (state machine, segment
                   packing).  No OS-specific code.
  ip/           -- IP / Ethernet header pack-and-parse helpers.

The pure-protocol code in tcp/ and ip/ must remain importable on every
platform we target -- it is exercised by unit tests even on hosts that
do not have a working pcap install.

Capability detection: importing this package does NOT load any DLL or
shared object.  Callers ask `pcap.get_backend()` for the platform
backend; that call is what attempts the ctypes load and raises
PcapUnavailableError on failure.  This keeps every other aionetiface
import path free of side-effects on hosts without pcap installed.
"""
from .backend import Backend, PcapUnavailableError, PcapError, get_backend, list_backends

__all__ = (
    "Backend",
    "PcapError",
    "PcapUnavailableError",
    "get_backend",
    "list_backends",
)
