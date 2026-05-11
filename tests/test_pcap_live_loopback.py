"""Live loopback test for the pcap-based userspace TCP stack.

This test:
  - Opens pcap on the local loopback interface
  - Builds two Connection objects in the same process
  - Drives both a normal three-way handshake and a simultaneous-open
  - Asserts a 1024-byte send/recv round-trip works in both cases

Skips cleanly if pcap can't be opened (no CAP_NET_RAW / no root).
Designed to be run as root on Linux/Fedora (DLT_EN10MB lo) and on
FreeBSD/GhostBSD/macOS where the loopback datalink is DLT_NULL.

Local-port allocation note:
  We use a high, randomised local port and a small fixed pool of
  destination ports.  The kernel doesn't bind on these ports for us
  (we never call socket.bind), but if the kernel happens to have an
  open socket on the same four-tuple the userspace stack may see
  unwanted RSTs.  Picking ports in the >40000 ephemeral range
  minimises that.

Loopback rewrite gotcha:
  On every loopback we test against, packets travelling through
  the loopback driver are written through to *both* sides of the pcap
  handle by the kernel.  That means a single Connection's outbound
  segment is seen by *its own* recv() (loopback echo) -- the FourTuple
  filter in conn.process_frame discards it because src_port belongs to
  ourselves.  Important: both Connections must use *different* local
  ports for the simul-open test or each will mistake its own emission
  for the peer's response.
"""
import asyncio
import os
import random
import socket
import sys
import unittest

from aionetiface.testing import AsyncTestCase

from aionetiface.net.pcap import get_backend, PcapUnavailableError, PcapError
from aionetiface.net.pcap.tcp.conn import Connection


LOOPBACK_IP = "127.0.0.1"


def loopback_iface_name():
    if sys.platform.startswith("linux"):
        return "lo"
    if sys.platform.startswith("darwin") or sys.platform.startswith("freebsd") \
       or sys.platform.startswith("openbsd") or sys.platform.startswith("netbsd"):
        return "lo0"
    return None


class TestLiveLoopback(AsyncTestCase):

    async def asyncSetUp(self):
        try:
            self.factory = get_backend()
        except PcapUnavailableError as exc:
            self.skipTest("pcap not installed: {0}".format(exc))
        if not self.factory.available():
            self.skipTest("pcap factory not available")
        self.iface = loopback_iface_name()
        if self.iface is None:
            self.skipTest("no loopback iface known for {0}".format(sys.platform))
        # Each Connection needs its own Backend (one pcap_t per
        # capture) -- they share the loopback interface but get their
        # own ring buffer.
        try:
            self.backend_a = self.factory.open(self.iface, timeout_ms=10)
            self.backend_b = self.factory.open(self.iface, timeout_ms=10)
        except PcapError as exc:
            self.skipTest("open loopback failed (need CAP_NET_RAW/root): {0}".format(exc))
        # Apply a tight BPF filter so the test doesn't drown in unrelated
        # loopback traffic.  Both backends see the same port range; the
        # per-connection FourTuple filter does the final split.
        # The port range is generated lazily in each test method.
        self.conns = []

    async def asyncTearDown(self):
        for c in self.conns:
            try:
                await c.close()
            except Exception:
                pass
        try:
            self.backend_a.close()
        except Exception:
            pass
        try:
            self.backend_b.close()
        except Exception:
            pass

    def pick_ports(self):
        """Three high-ephemeral ports that aren't currently bound by
        the kernel.  We don't actually bind these -- we just want a
        very low collision probability with kernel sockets."""
        # Random offset prevents back-to-back tests in the same process
        # from colliding with the previous run's lingering segments.
        base = 45000 + (os.getpid() % 1000) + random.randint(0, 1000)
        return base, base + 1

    async def drive_handshake_normal(self, listener, connector):
        """Wait for both sides to reach ESTABLISHED."""
        await asyncio.gather(
            listener.wait_established(timeout=4.0),
            connector.wait_established(timeout=4.0),
        )

    async def test_three_way_handshake(self):
        port_a, port_b = self.pick_ports()
        listener = Connection(self.backend_a, LOOPBACK_IP)
        connector = Connection(self.backend_b, LOOPBACK_IP)
        self.conns.extend([listener, connector])
        await listener.start_listen(port_a, remote_ip=LOOPBACK_IP, remote_port=port_b)
        # Tight BPF on the listener to drop unrelated loopback noise.
        try:
            self.backend_a.set_filter(
                "tcp and port {0} and port {1}".format(port_a, port_b))
        except PcapError:
            pass
        try:
            self.backend_b.set_filter(
                "tcp and port {0} and port {1}".format(port_a, port_b))
        except PcapError:
            pass
        await asyncio.sleep(0.1)  # let listener's driver start
        await connector.start_active(
            remote_ip=LOOPBACK_IP, remote_port=port_a,
            local_port=port_b, simul=False)
        try:
            await self.drive_handshake_normal(listener, connector)
        except Exception as exc:
            self.fail("3-way handshake did not complete: {0}".format(exc))

        # 1024-byte round-trip.
        payload = bytes(bytearray(random.randint(0, 255) for _ in range(1024)))
        await connector.send(payload)
        chunks = []
        deadline = asyncio.get_event_loop().time() + 5.0
        while sum(len(c) for c in chunks) < len(payload):
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            chunk = await listener.recv(2048, timeout=remaining)
            if not chunk:
                break
            chunks.append(chunk)
        got = b"".join(chunks)
        self.assertEqual(got, payload, "received {0} of {1} bytes".format(
            len(got), len(payload)))

    async def test_simul_open(self):
        port_a, port_b = self.pick_ports()
        a = Connection(self.backend_a, LOOPBACK_IP)
        b = Connection(self.backend_b, LOOPBACK_IP)
        self.conns.extend([a, b])
        try:
            self.backend_a.set_filter(
                "tcp and port {0} and port {1}".format(port_a, port_b))
            self.backend_b.set_filter(
                "tcp and port {0} and port {1}".format(port_a, port_b))
        except PcapError:
            pass
        # Both sides start_active with simul=True -- they should both
        # transmit a bare SYN, see each other's SYN, transition through
        # SYN_RECEIVED, and end up in ESTABLISHED.
        await asyncio.gather(
            a.start_active(
                remote_ip=LOOPBACK_IP, remote_port=port_b,
                local_port=port_a, simul=True),
            b.start_active(
                remote_ip=LOOPBACK_IP, remote_port=port_a,
                local_port=port_b, simul=True),
        )
        try:
            await asyncio.gather(
                a.wait_established(timeout=6.0),
                b.wait_established(timeout=6.0),
            )
        except Exception as exc:
            self.fail("simul-open did not complete: {0}".format(exc))

        payload = bytes(bytearray(random.randint(0, 255) for _ in range(1024)))
        await a.send(payload)
        chunks = []
        deadline = asyncio.get_event_loop().time() + 5.0
        while sum(len(c) for c in chunks) < len(payload):
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            chunk = await b.recv(2048, timeout=remaining)
            if not chunk:
                break
            chunks.append(chunk)
        got = b"".join(chunks)
        self.assertEqual(got, payload, "received {0} of {1} bytes".format(
            len(got), len(payload)))


if __name__ == "__main__":
    unittest.main()
