"""Unit tests for the PipeShim adapter.

PipeShim wraps a userspace pcap Connection in a Pipe-shaped duck-type
surface. These tests use a MockConnection so we exercise only the
shim's adapter logic (send forwarding, recv routing, subscribe
lifecycle, close ordering, firewall callback, on_close).

Run with: ~/.pyenv/versions/3.5.10/bin/python -m unittest tests.test_pcap_pipe_shim
"""
import asyncio
import unittest

from aionetiface.testing import AsyncTestCase
from aionetiface.net.pcap.tcp.pipe_shim import PipeShim, hash_sub
from aionetiface.net.net_defs import SUB_ALL, TCP


class MockTcpState(object):
    """Smallest TcpState stub: just the fields PipeShim.close_watcher
    and PipeShim.close interact with via Connection."""

    def __init__(self):
        self.aborted = False
        self.state = "ESTABLISHED"


class MockConnection(object):
    """Minimal stand-in for aionetiface.net.pcap.tcp.conn.Connection.

    Behaviour:
      - send(buf) appends to ``self.sent`` and returns len(buf).
      - recv(n, timeout) blocks on an internal asyncio.Queue feeding
        outbound bytes (test pushes via ``self.queue_inbound``);
        returns b"" when ``feed_eof`` is called.
      - close() flips closed_event and the state.
    Also exposes ``ft`` so PipeShim can build a client_tup from it.
    """

    def __init__(self, loop, peer_ip="1.2.3.4", peer_port=4242):
        self.loop = loop
        self.sent = []
        self.recv_queue = asyncio.Queue()
        self.closed_event = asyncio.Event()
        self.state = MockTcpState()
        self.close_called = 0

        # FourTuple-shape with only the fields PipeShim reads.
        class FT(object):
            pass

        self.ft = FT()
        self.ft.local_ip = "5.6.7.8"
        self.ft.local_port = 9000
        self.ft.remote_ip = peer_ip
        self.ft.remote_port = peer_port

    async def send(self, data):
        if self.closed_event.is_set():
            raise RuntimeError("send after close")
        self.sent.append(bytes(data))
        return len(data)

    async def recv(self, n=4096, timeout=None):
        if self.closed_event.is_set():
            return b""
        # Pull next chunk; honour an explicit None sentinel (eof).
        if timeout is None:
            item = await self.recv_queue.get()
        else:
            item = await asyncio.wait_for(self.recv_queue.get(), timeout)
        if item is None:
            return b""
        return item

    def queue_inbound(self, data):
        """Test helper: simulate a frame arrived at the Connection."""
        self.recv_queue.put_nowait(data)

    def feed_eof(self):
        self.recv_queue.put_nowait(None)
        self.closed_event.set()

    async def close(self):
        self.close_called += 1
        self.closed_event.set()
        # Also feed an eof so an in-flight recv pump wakes up.
        try:
            self.recv_queue.put_nowait(None)
        except asyncio.QueueFull:
            pass


class TestPipeShim(AsyncTestCase):
    """PipeShim adapter unit tests."""

    async def asyncSetUp(self):
        self.loop = asyncio.get_event_loop()
        self.conn = MockConnection(self.loop)
        self.fw_called = []

        def fw_cb():
            self.fw_called.append(True)

        self.shim = PipeShim(
            self.conn,
            client_tup=("1.2.3.4", 4242),
            firewall_teardown=fw_cb,
            loop=self.loop,
        )

    async def asyncTearDown(self):
        if not self.shim.closed:
            try:
                await asyncio.wait_for(self.shim.close(), timeout=2)
            except (asyncio.TimeoutError, Exception):
                pass

    async def test_proto_is_tcp(self):
        self.assertEqual(self.shim.proto, TCP)
        self.assertEqual(self.shim.pipe_events.proto, TCP)

    async def test_client_tup_propagates(self):
        self.assertEqual(self.shim.client_tup, ("1.2.3.4", 4242))
        self.assertEqual(self.shim.pipe_events.client_tup, ("1.2.3.4", 4242))

    async def test_send_forwards_to_connection(self):
        n = await self.shim.send(b"hello world")
        self.assertEqual(n, len(b"hello world"))
        self.assertEqual(self.conn.sent, [b"hello world"])

    async def test_multiple_sends_dont_drop(self):
        for i in range(8):
            buf = b"chunk-" + str(i).encode("ascii") + b"-" + b"x" * 100
            n = await self.shim.send(buf)
            self.assertEqual(n, len(buf))
        self.assertEqual(len(self.conn.sent), 8)
        # Round-trip every byte to make sure ordering preserved.
        self.assertIn(b"chunk-7-", self.conn.sent[7])

    async def test_recv_returns_queued_bytes(self):
        self.shim.subscribe(SUB_ALL)
        self.conn.queue_inbound(b"first")
        msg = await self.shim.recv(SUB_ALL, timeout=2)
        self.assertEqual(msg, b"first")

    async def test_recv_auto_subscribes(self):
        # No explicit subscribe -- recv should still work.
        self.conn.queue_inbound(b"auto-sub")
        msg = await self.shim.recv(SUB_ALL, timeout=2)
        self.assertEqual(msg, b"auto-sub")

    async def test_recv_timeout_returns_none(self):
        self.shim.subscribe(SUB_ALL)
        msg = await self.shim.recv(SUB_ALL, timeout=0.1)
        self.assertIsNone(msg)

    async def test_recv_full_returns_client_tup_pair(self):
        self.shim.subscribe(SUB_ALL)
        self.conn.queue_inbound(b"full-form")
        ret = await self.shim.recv(SUB_ALL, timeout=2, full=True)
        self.assertEqual(ret[0], ("1.2.3.4", 4242))
        self.assertEqual(ret[1], b"full-form")

    async def test_subscribe_unsubscribe_lifecycle(self):
        offset = self.shim.subscribe(SUB_ALL)
        self.assertIn(offset, self.shim.stream.subs)
        self.shim.unsubscribe(SUB_ALL)
        self.assertNotIn(offset, self.shim.stream.subs)

    async def test_close_calls_connection_close(self):
        await self.shim.close()
        self.assertEqual(self.conn.close_called, 1)
        self.assertTrue(self.shim.closed)

    async def test_close_calls_firewall_teardown(self):
        await self.shim.close()
        self.assertEqual(self.fw_called, [True])

    async def test_close_firewall_runs_even_when_connection_close_raises(self):
        async def boom():
            raise OSError("boom")

        self.conn.close = boom
        try:
            await self.shim.close()
        except OSError:
            pass
        # Firewall callback MUST have run.
        self.assertEqual(self.fw_called, [True])

    async def test_close_is_idempotent(self):
        await self.shim.close()
        await self.shim.close()
        self.assertEqual(self.conn.close_called, 1)
        self.assertEqual(self.fw_called, [True])

    async def test_on_close_set_when_connection_closes(self):
        # Watcher should fire on_close when Connection.closed_event sets.
        self.assertFalse(self.shim.on_close.is_set())
        self.conn.feed_eof()
        # Let the watcher loop pick up the event.
        try:
            await asyncio.wait_for(self.shim.on_close.wait(), timeout=2)
        except asyncio.TimeoutError:
            self.fail("on_close did not fire when Connection closed")
        self.assertTrue(self.shim.on_close.is_set())

    async def test_pipe_events_stream_subs_is_dict(self):
        # gate.Link(managed=True) does pipe.pipe_events.stream.subs = {}
        # -- verify that surface is real and writable.
        self.shim.pipe_events.stream.subs = {}
        self.assertEqual(self.shim.pipe_events.stream.subs, {})

    async def test_send_after_close_returns_zero(self):
        await self.shim.close()
        n = await self.shim.send(b"too late")
        self.assertEqual(n, 0)

    async def test_recv_wakes_on_close_with_none(self):
        self.shim.subscribe(SUB_ALL)
        # Start a recv in the background, then close.
        recv_task = asyncio.ensure_future(
            self.shim.recv(SUB_ALL, timeout=10),
        )
        await asyncio.sleep(0.05)
        await self.shim.close()
        msg = await asyncio.wait_for(recv_task, timeout=2)
        self.assertIsNone(msg)


class TestHashSub(unittest.TestCase):
    """Lightweight tests for hash_sub matching PipeClient semantics."""

    def test_sub_all_consistent(self):
        a = hash_sub([None, None])
        b = hash_sub([None, None])
        self.assertEqual(a, b)

    def test_with_client_tup(self):
        sub_a = [b"prefix", ("1.2.3.4", 80)]
        sub_b = [b"prefix", ("1.2.3.4", 80)]
        self.assertEqual(hash_sub(sub_a), hash_sub(sub_b))

    def test_different_patterns_differ(self):
        a = hash_sub([b"alpha", None])
        b = hash_sub([b"beta", None])
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
