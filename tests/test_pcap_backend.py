"""Phase-1 smoke test for the pcap backend abstraction.

What this exercises:
  * import time: pcap module loads on every platform without pulling
    ctypes-bound symbols (none of the os/<x>.py shims is imported
    until get_backend() is called explicitly).
  * loaded shim: matches sys.platform.
  * if libpcap / wpcap.dll is actually installed:
      - list_interfaces() returns something non-empty
      - opening the loopback interface succeeds
      - a BPF filter compiles
      - injecting and reading back a probe frame round-trips

If pcap is not installed, every check after the import smoke test
is skipTest -- this lets the test file pass in CI environments
that don't have libpcap-devel / WinPcap.

Loopback frame format note:
  - DLT_EN10MB (Linux "lo"): 14-byte Ethernet header with src/dst MAC
    both 00:00:00:00:00:00 + EtherType.  We use a private EtherType
    0x88B5 (IEEE 802 reserved for "Local Experimental EtherType 1",
    https://standards.ieee.org/products-programs/regauth/ethertype/)
    so the probe frame is unambiguously ours and the host kernel
    drops it as unknown -- which is what we want; we only ever read
    it through pcap.
  - DLT_NULL (BSD lo0): 4-byte AF_* prefix instead of Ethernet.
    Phase 1 only needs to *send and receive bytes*, so we just dump
    14 bytes of zeros + the payload and accept whatever loopback
    framing the OS uses; the Phase-2 IP/eth layer will care about
    the difference.

References:
  - DLT_NULL framing: https://www.tcpdump.org/manpages/pcap-savefile.5.html
  - Local experimental EtherTypes:
    https://standards-oui.ieee.org/ethertype/eth.txt
"""
import os
import unittest

from aionetiface.testing import AsyncTestCase

from aionetiface.net.pcap import (
    Backend, PcapError, PcapUnavailableError, get_backend, list_backends,
)
from aionetiface.net.pcap.backend import pick_module_name
from aionetiface.net.pcap.loopback import PcapReader


# Magic probe payload -- unique enough to not collide with whatever
# else is on the loopback interface during a test run.
PROBE_MAGIC = b"AIONETIFACE_PCAP_PROBE_v1_" + os.urandom(8)
EXPERIMENTAL_ETHERTYPE = 0x88B5


def loopback_iface_name():
    """Best-effort guess at the local loopback iface name for the
    current platform.  Tests skipTest when this returns None."""
    import sys
    plat = sys.platform
    if plat.startswith("linux"):
        return "lo"
    if plat.startswith("darwin") or plat.startswith("freebsd") or \
       plat.startswith("openbsd") or plat.startswith("netbsd"):
        return "lo0"
    # Windows: NPF interface names are GUID-based and not predictable;
    # the test below picks one from list_interfaces() with loopback=True.
    return None


class TestPcapImportSmoke(AsyncTestCase):
    """No native code required -- just verifies the import machinery
    behaves cleanly on every platform."""

    async def test_module_listing_is_stable(self):
        backends = list_backends()
        self.assertTrue(len(backends) >= 3)
        names = set(name for name, _ in backends)
        # Must cover every platform we care about.
        self.assertIn("linux", names)
        self.assertIn("win32", names)
        self.assertIn("darwin", names)

    async def test_pick_module_name_known(self):
        # Linux maps to the linux shim regardless of suffix.
        self.assertEqual(
            pick_module_name("linux"),
            "aionetiface.net.pcap.os.linux",
        )
        self.assertEqual(
            pick_module_name("linux2"),
            "aionetiface.net.pcap.os.linux",
        )
        self.assertEqual(
            pick_module_name("win32"),
            "aionetiface.net.pcap.os.windows",
        )
        self.assertEqual(
            pick_module_name("darwin"),
            "aionetiface.net.pcap.os.darwin",
        )

    async def test_pick_module_name_unknown_raises(self):
        with self.assertRaises(PcapUnavailableError):
            pick_module_name("plan9")


class TestPcapBackendLive(AsyncTestCase):
    """Live test against the platform's pcap library.  Skips when
    no library is loadable."""

    async def asyncSetUp(self):
        try:
            self.factory = get_backend()
        except PcapUnavailableError as exc:
            self.skipTest("pcap not installed: {0}".format(exc))
        if not self.factory.available():
            self.skipTest("pcap factory reports unavailable")
        self.backend = None
        self.reader = None

    async def asyncTearDown(self):
        if self.reader is not None:
            self.reader.stop()
        if self.backend is not None:
            try:
                self.backend.close()
            except PcapError:
                pass

    async def test_library_version_string(self):
        v = self.factory.library_version()
        self.assertIsNotNone(v)
        self.assertIsInstance(v, str)
        print("pcap library_version: {0}".format(v))

    async def test_list_interfaces_returns_data(self):
        ifaces = self.factory.list_interfaces()
        self.assertIsInstance(ifaces, list)
        # Most boxes have at least one capturable interface.  If not,
        # skip rather than fail -- some sandboxes give a network
        # namespace with no pcap-accessible iface.
        if not ifaces:
            self.skipTest("no pcap interfaces visible")
        for entry in ifaces:
            self.assertIn("name", entry)
            self.assertIn("addresses", entry)
        # Useful diagnostic on test failures elsewhere.
        for entry in ifaces[:5]:
            print("pcap iface: name={0} loopback={1} addrs={2}".format(
                entry.get("name"), entry.get("loopback"),
                entry.get("addresses"),
            ))

    def pick_loopback(self):
        name = loopback_iface_name()
        if name is not None:
            return name
        # Windows / unknown -- find a loopback in the listing.
        for entry in self.factory.list_interfaces():
            if entry.get("loopback"):
                return entry["name"]
        return None

    async def test_open_loopback_and_set_filter(self):
        iface = self.pick_loopback()
        if iface is None:
            self.skipTest("no loopback interface visible")
        try:
            self.backend = self.factory.open(iface, timeout_ms=10)
        except PcapError as exc:
            # On Linux this typically means EPERM -- CAP_NET_RAW not set.
            self.skipTest("could not open {0}: {1}".format(iface, exc))
        self.assertIsInstance(self.backend, Backend)
        # Empty filter is allowed; a real one must compile.
        self.backend.set_filter("")
        self.backend.set_filter("udp or tcp")

    async def test_send_and_receive_probe_frame(self):
        iface = self.pick_loopback()
        if iface is None:
            self.skipTest("no loopback interface visible")
        try:
            self.backend = self.factory.open(iface, timeout_ms=20)
        except PcapError as exc:
            self.skipTest("could not open {0}: {1}".format(iface, exc))

        # Build a probe frame.  For DLT_EN10MB we synthesise an
        # all-zero Ethernet header; for DLT_NULL we send a 4-byte
        # AF prefix.  The kernel will drop the frame on its way out
        # (no protocol stack will consume it), but pcap captures both
        # sides so we should see it land on our recv() side.
        from aionetiface.net.pcap.os.libpcap_core import DLT_EN10MB, DLT_NULL, DLT_LOOP
        dlt = self.backend.datalink()
        if dlt == DLT_EN10MB:
            header = b"\x00\x00\x00\x00\x00\x00" * 2 + bytes([
                EXPERIMENTAL_ETHERTYPE >> 8, EXPERIMENTAL_ETHERTYPE & 0xff
            ])
        elif dlt == DLT_NULL:
            # AF_INET = 2 little-endian on BSD lo0
            header = b"\x02\x00\x00\x00"
        elif dlt == DLT_LOOP:
            # OpenBSD: same as DLT_NULL but big-endian AF_INET
            header = b"\x00\x00\x00\x02"
        else:
            self.skipTest("unsupported loopback datalink {0}".format(dlt))

        frame = header + PROBE_MAGIC + b"\x00" * 32  # pad to >= 64
        # Filter so we only see our own probe payload echoed back.
        try:
            # A "udp" filter would miss the unknown EtherType; use a
            # raw-byte filter that matches anywhere in the packet.
            # The simplest portable BPF for that is to match by length
            # at a stable offset.  We don't actually filter here -- we
            # let the reader thread see everything and we match in
            # Python.  That keeps the test platform-portable.
            self.backend.set_filter("")
        except PcapError as exc:
            self.skipTest("set_filter failed: {0}".format(exc))

        # Start the async reader before we send so we don't race.
        import asyncio
        loop = asyncio.get_event_loop()
        self.reader = PcapReader(self.backend, loop=loop, poll_ms=20)
        self.reader.start()

        try:
            sent = self.backend.send(frame)
        except PcapError as exc:
            # Some loopback drivers (DLT_NULL on macOS in particular)
            # refuse pcap_sendpacket().  That's a known libpcap-level
            # limitation, not a bug in our backend.
            self.skipTest("pcap_sendpacket failed on {0}: {1}".format(iface, exc))
        self.assertEqual(sent, len(frame))

        # Loop a few times in case there's other loopback traffic in
        # the queue before our probe.
        import time
        deadline = time.time() + 3.0
        saw_probe = False
        while time.time() < deadline:
            try:
                got = await self.reader.next_frame(timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if got is None:
                break
            if PROBE_MAGIC in got:
                saw_probe = True
                break
        self.assertTrue(
            saw_probe,
            "did not observe our own probe frame on loopback within 3s",
        )


if __name__ == "__main__":
    unittest.main()
