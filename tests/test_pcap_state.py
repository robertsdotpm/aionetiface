"""TCP state-machine unit tests.

Drives TcpState directly with crafted TcpSegment inputs (no pcap I/O,
no asyncio) and asserts:

  - normal three-way handshake completes (active + passive)
  - simultaneous-open completes (both sides start in SYN_SENT, swap
    bare-SYNs, both reach ESTABLISHED)
  - data transfer in ESTABLISHED forwards bytes both directions
  - graceful close (FIN-WAIT-1, FIN-WAIT-2, TIME-WAIT for one side;
    CLOSE-WAIT, LAST-ACK, CLOSED on the other)
  - peer RST in any synchronised state aborts

Where the spec text below references RFC 9293, the corresponding
section number is included as a comment so future tightening / fuzzing
has a paper trail.
"""
import unittest

from aionetiface.testing import AsyncTestCase

from aionetiface.net.pcap.tcp.state import (
    TcpState, CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSING,
)
from aionetiface.net.pcap.tcp.segment import (
    TcpSegment, FLAG_SYN, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_PSH,
    build_mss_option,
)


def pop_one(state):
    """Pop the first segment off state.outbox; assert it exists."""
    assert state.outbox, "expected at least one outbound segment"
    return state.outbox.pop(0)


def drain(state):
    out, state.outbox = state.outbox, []
    return out


def make_segment(src_port, dst_port, seq, ack, flags, payload=b"", window=65535):
    return TcpSegment(
        src_port=src_port, dst_port=dst_port, seq=seq, ack=ack,
        flags=flags, payload=payload, window=window,
        options=build_mss_option(1460) if flags & FLAG_SYN else b"",
    )


class TestNormalHandshake(AsyncTestCase):
    """Three-way: client SYN -> server SYN+ACK -> client ACK."""

    async def test_active_opener_path(self):
        client = TcpState("10.0.0.1", 4444)
        client.open_active("10.0.0.2", 5555)
        self.assertEqual(client.state, SYN_SENT)
        syn = pop_one(client)
        self.assertTrue(syn.has_flag(FLAG_SYN))
        self.assertFalse(syn.has_flag(FLAG_ACK))

        # Server replies SYN+ACK with seq=200, ack=syn.seq+1
        synack = make_segment(5555, 4444, 200, (syn.seq + 1) & 0xffffffff,
                              FLAG_SYN | FLAG_ACK)
        ok = client.on_segment(synack, "10.0.0.2")
        self.assertTrue(ok)
        self.assertEqual(client.state, ESTABLISHED)
        ack = pop_one(client)
        self.assertTrue(ack.has_flag(FLAG_ACK))
        self.assertFalse(ack.has_flag(FLAG_SYN))
        self.assertEqual(ack.ack, 201)

    async def test_passive_opener_path(self):
        server = TcpState("10.0.0.2", 5555)
        server.open_listen()
        self.assertEqual(server.state, LISTEN)

        client_syn = make_segment(4444, 5555, 100, 0, FLAG_SYN)
        ok = server.on_segment(client_syn, "10.0.0.1")
        self.assertTrue(ok)
        self.assertEqual(server.state, SYN_RECEIVED)
        synack = pop_one(server)
        self.assertTrue(synack.has_flag(FLAG_SYN))
        self.assertTrue(synack.has_flag(FLAG_ACK))
        self.assertEqual(synack.ack, 101)

        # Client final ACK.
        ack = make_segment(4444, 5555, 101, (synack.seq + 1) & 0xffffffff,
                           FLAG_ACK)
        ok = server.on_segment(ack, "10.0.0.1")
        self.assertTrue(ok)
        self.assertEqual(server.state, ESTABLISHED)


class TestSimulOpen(AsyncTestCase):
    """The XP bypass: both sides simultaneously open, exchange bare SYNs."""

    async def test_simul_open_completes(self):
        a = TcpState("10.0.0.1", 4444)
        b = TcpState("10.0.0.2", 5555)
        a.open_simul("10.0.0.2", 5555)
        b.open_simul("10.0.0.1", 4444)
        self.assertEqual(a.state, SYN_SENT)
        self.assertEqual(b.state, SYN_SENT)

        a_syn = pop_one(a)
        b_syn = pop_one(b)
        self.assertTrue(a_syn.has_flag(FLAG_SYN))
        self.assertFalse(a_syn.has_flag(FLAG_ACK))
        self.assertTrue(b_syn.has_flag(FLAG_SYN))
        self.assertFalse(b_syn.has_flag(FLAG_ACK))

        # Each side now receives the *other's* bare SYN.  RFC 9293
        # sec 3.10.7.4 says move to SYN_RECEIVED and emit SYN+ACK.
        self.assertTrue(a.on_segment(b_syn, "10.0.0.2"))
        self.assertEqual(a.state, SYN_RECEIVED)
        self.assertTrue(b.on_segment(a_syn, "10.0.0.1"))
        self.assertEqual(b.state, SYN_RECEIVED)

        a_synack = pop_one(a)
        b_synack = pop_one(b)
        self.assertTrue(a_synack.has_flag(FLAG_SYN))
        self.assertTrue(a_synack.has_flag(FLAG_ACK))
        self.assertEqual(a_synack.seq, a.iss)
        self.assertEqual(a_synack.ack, (b.iss + 1) & 0xffffffff)
        self.assertTrue(b_synack.has_flag(FLAG_SYN))
        self.assertTrue(b_synack.has_flag(FLAG_ACK))

        # Now each side receives the other's SYN+ACK.  In SYN_RECEIVED
        # this matches the "retransmitted SYN+ACK + the ACK that proves
        # our SYN got there" case.
        self.assertTrue(a.on_segment(b_synack, "10.0.0.2"))
        self.assertEqual(a.state, ESTABLISHED)
        self.assertTrue(b.on_segment(a_synack, "10.0.0.1"))
        self.assertEqual(b.state, ESTABLISHED)


class TestDataTransfer(AsyncTestCase):

    async def test_send_receive_payload(self):
        client = TcpState("10.0.0.1", 4444)
        server = TcpState("10.0.0.2", 5555)
        client.open_active("10.0.0.2", 5555)
        syn = pop_one(client)
        server.open_listen()
        server.on_segment(syn, "10.0.0.1")
        synack = pop_one(server)
        client.on_segment(synack, "10.0.0.2")
        ack = pop_one(client)
        server.on_segment(ack, "10.0.0.1")
        # Both ESTABLISHED -- clear outboxes.
        drain(client)
        drain(server)

        # Client sends 200 bytes -> server.
        client.write(b"A" * 200)
        seg = pop_one(client)
        self.assertEqual(seg.payload, b"A" * 200)
        server.on_segment(seg, "10.0.0.1")
        # Server should ACK + buffer the payload.
        self.assertEqual(server.pop_read(), b"A" * 200)
        ack = pop_one(server)
        self.assertTrue(ack.has_flag(FLAG_ACK))
        # Feeding the ACK back to client clears the unacked flag.
        client.on_segment(ack, "10.0.0.2")
        self.assertFalse(client.have_unacked)


class TestGracefulClose(AsyncTestCase):

    async def test_active_close(self):
        # Walk both sides up to ESTABLISHED.
        a = TcpState("10.0.0.1", 4444)
        b = TcpState("10.0.0.2", 5555)
        a.open_active("10.0.0.2", 5555)
        b.open_listen()
        b.on_segment(pop_one(a), "10.0.0.1")
        a.on_segment(pop_one(b), "10.0.0.2")
        b.on_segment(pop_one(a), "10.0.0.1")
        drain(a)
        drain(b)

        # 'a' initiates close.
        a.close()
        self.assertEqual(a.state, FIN_WAIT_1)
        fin1 = pop_one(a)
        self.assertTrue(fin1.has_flag(FLAG_FIN))
        # 'b' receives FIN -> CLOSE_WAIT, sends ACK.
        b.on_segment(fin1, "10.0.0.1")
        self.assertEqual(b.state, CLOSE_WAIT)
        ack = pop_one(b)
        self.assertTrue(ack.has_flag(FLAG_ACK))
        # 'a' receives ACK -> FIN_WAIT_2 (b hasn't FINned yet).
        a.on_segment(ack, "10.0.0.2")
        self.assertEqual(a.state, FIN_WAIT_2)
        # 'b' closes -> sends FIN -> LAST_ACK.
        b.close()
        self.assertEqual(b.state, LAST_ACK)
        b_fin = pop_one(b)
        # 'a' receives 'b's FIN -> TIME_WAIT (+ ACK).
        a.on_segment(b_fin, "10.0.0.2")
        self.assertEqual(a.state, TIME_WAIT)
        a_final = pop_one(a)
        self.assertTrue(a_final.has_flag(FLAG_ACK))
        # 'b' receives final ACK -> CLOSED.
        b.on_segment(a_final, "10.0.0.1")
        self.assertEqual(b.state, CLOSED)


class TestRst(AsyncTestCase):

    async def test_rst_aborts_established(self):
        a = TcpState("10.0.0.1", 4444)
        b = TcpState("10.0.0.2", 5555)
        a.open_active("10.0.0.2", 5555)
        b.open_listen()
        b.on_segment(pop_one(a), "10.0.0.1")
        a.on_segment(pop_one(b), "10.0.0.2")
        b.on_segment(pop_one(a), "10.0.0.1")
        drain(a)
        drain(b)

        # 'b' RSTs.
        rst = make_segment(5555, 4444, b.snd_nxt, a.rcv_nxt, FLAG_RST | FLAG_ACK)
        a.on_segment(rst, "10.0.0.2")
        self.assertTrue(a.aborted)
        self.assertEqual(a.state, CLOSED)

    async def test_off_path_rst_in_syn_sent_ignored(self):
        # A RST in SYN_SENT must only abort if it acks our SYN -- this
        # is the explicit defence against off-path RSTs on the XP path.
        a = TcpState("10.0.0.1", 4444)
        a.open_active("10.0.0.2", 5555)
        syn = pop_one(a)
        bad_rst = make_segment(5555, 4444, 0, 9999, FLAG_RST | FLAG_ACK)
        a.on_segment(bad_rst, "10.0.0.2")
        self.assertFalse(a.aborted)
        self.assertEqual(a.state, SYN_SENT)


class TestRejectOffTuple(AsyncTestCase):

    async def test_wrong_src_ip_in_established_dropped(self):
        a = TcpState("10.0.0.1", 4444)
        b = TcpState("10.0.0.2", 5555)
        a.open_active("10.0.0.2", 5555)
        b.open_listen()
        b.on_segment(pop_one(a), "10.0.0.1")
        a.on_segment(pop_one(b), "10.0.0.2")
        b.on_segment(pop_one(a), "10.0.0.1")
        drain(a)
        drain(b)

        injected = make_segment(5555, 4444, a.rcv_nxt, a.snd_nxt,
                                FLAG_ACK | FLAG_PSH, payload=b"INJECT")
        # Drop because src_ip=evil != 10.0.0.2
        ok = a.on_segment(injected, "10.0.0.99")
        self.assertFalse(ok)
        self.assertEqual(a.pop_read(), b"")


if __name__ == "__main__":
    unittest.main()
