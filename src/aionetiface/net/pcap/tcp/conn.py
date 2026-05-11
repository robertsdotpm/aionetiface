"""Userspace TCP Connection -- Pipe-compatible facade.

Bridges:
    pcap Backend (raw frames in/out)
        +
    ip.eth / ip.ipv4 (link/IP layer pack/unpack)
        +
    tcp.segment + tcp.state (the FSM)
        +
    asyncio  (so callers can await send/recv like the rest of p2pd)

Public API (subset of the aionetiface Pipe contract):
    Connection.send(data) -- coroutine, return when bytes are buffered
    Connection.recv(n)    -- coroutine, return up to n bytes
    Connection.close()    -- coroutine, FIN dance
    Connection.is_open    -- bool

The Pipe layer in aionetiface (see net/pipe/pipe.py) is a duck-typed
contract: anything with these four members can be plugged into
auto_connect.  No subclass relationship required.

This module deliberately stays small.  Reuse via composition: the
plugin in p2pd wraps a Connection in whatever it needs.

Datalink handling:
    DLT_EN10MB: full Ethernet + IP + TCP stack; we lookup peer MAC from
        an ArpCache (with optional ARP request when miss).
    DLT_NULL / DLT_LOOP: no Ethernet; we wrap with the BSD AF_ prefix.
    DLT_RAW: just IP + TCP; the test path on linux "lo" can also use
        DLT_EN10MB (which is what libpcap reports) -- we handle both.
"""
import asyncio
import socket as stdlib_socket

from ..ip import eth, ipv4
from . import segment as tcp_segment
from .state import TcpState, ESTABLISHED, CLOSED
from .simul_open import FourTuple, match_inbound

try:
    from ....utility.fstr import fstr
except ImportError:
    def fstr(template, args):
        return template.format(*args)


class ConnectionError2(Exception):
    """Wrapper for any error escaping the pcap-stack on the way to the
    caller.  Named with the `2` suffix so we don't shadow Python 3's
    built-in ConnectionError."""


class Connection(object):
    """One userspace TCP connection driven over a pcap Backend.

    Lifecycle on the connector side:
        backend = factory.open(iface_name)
        conn = Connection(backend, local_ip, local_mac)
        await conn.start_active(remote_ip, remote_mac, remote_port,
                                local_port, simul=True)
        await conn.send(b"hello")
        chunk = await conn.recv(1024)
        await conn.close()

    Lifecycle on the listener side:
        ...
        await conn.start_listen(local_port)
        # Listener accepts whichever peer first sends a SYN.
        await conn.wait_established(timeout=5)
        ...
    """

    def __init__(self, backend, local_ip, local_mac=None, loop=None,
                 reader=None):
        self.backend = backend
        self.local_ip = local_ip
        self.local_mac = (
            eth.parse_mac(local_mac) if isinstance(local_mac, str)
            else local_mac
        )
        self.loop = loop or asyncio.get_event_loop()
        self.reader = reader  # optional pre-created PcapReader
        self.owns_reader = reader is None

        self.state = None  # TcpState instance once configured
        self.ft = None     # FourTuple
        self.peer_mac = None
        self.arp_cache = eth.ArpCache()
        self.datalink = backend.datalink()

        self.read_waiters = []  # asyncio.Future objects waiting on data
        self.established_event = asyncio.Event()
        self.closed_event = asyncio.Event()
        self.driver_task = None
        self.retx_task = None

    # --- Setup paths ----------------------------------------------------

    async def start_active(self, remote_ip, remote_port, local_port,
                            remote_mac=None, simul=False, mss=1460):
        """Active opener.  If simul=True we go straight to SYN_SENT
        expecting the peer to do the same; otherwise standard 3-way."""
        self.state = TcpState(self.local_ip, local_port, mss=mss)
        self.ft = FourTuple(self.local_ip, local_port, remote_ip, remote_port)
        if remote_mac is not None:
            self.peer_mac = (
                eth.parse_mac(remote_mac) if isinstance(remote_mac, str)
                else remote_mac
            )
        await self.ensure_reader()
        self.start_driver()
        if simul:
            self.state.open_simul(remote_ip, remote_port)
        else:
            self.state.open_active(remote_ip, remote_port)
        self.flush_outbox()

    async def start_listen(self, local_port, remote_ip=None,
                            remote_port=None, mss=1460):
        """Server side.  If remote_ip/remote_port are given, we will
        only accept SYNs from that peer (useful for tcp_punch where
        the pair is pre-coordinated)."""
        self.state = TcpState(self.local_ip, local_port, mss=mss)
        self.state.open_listen()
        # If a peer pair is known, lock the four-tuple now -- it will be
        # updated on the first matching SYN.
        if remote_ip is not None and remote_port is not None:
            self.ft = FourTuple(self.local_ip, local_port,
                                remote_ip, remote_port)
        else:
            self.ft = None
        await self.ensure_reader()
        self.start_driver()

    async def ensure_reader(self):
        from ..loopback import PcapReader
        if self.reader is None:
            self.reader = PcapReader(self.backend, loop=self.loop, poll_ms=10)
            self.reader.start()
            self.owns_reader = True

    def start_driver(self):
        if self.driver_task is None:
            self.driver_task = self.loop.create_task(self.driver_loop())
        if self.retx_task is None:
            self.retx_task = self.loop.create_task(self.retx_loop())

    # --- Main driver loop ----------------------------------------------

    async def driver_loop(self):
        """Pull frames off the reader queue, push them through the FSM,
        emit any outbound segments.

        Runs until the state machine reaches CLOSED.
        """
        try:
            while True:
                if self.state is not None and self.state.is_closed():
                    break
                try:
                    frame = await asyncio.wait_for(
                        self.reader.next_frame(timeout=0.2), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                if frame is None:
                    # Reader died.
                    break
                try:
                    self.process_frame(frame)
                except Exception as exc:
                    # Don't let a bad frame kill the whole loop.
                    print(fstr(
                        "pcap conn: process_frame error {0}", (exc,)))
                self.flush_outbox()
                if self.state is not None and self.state.is_established():
                    if not self.established_event.is_set():
                        self.established_event.set()
                self.wake_readers()
        finally:
            self.closed_event.set()
            self.wake_readers()

    def process_frame(self, frame):
        """One captured frame -> at most one segment fed to the state."""
        try:
            ethertype, ip_payload = eth.strip_link_layer(self.datalink, frame)
        except ValueError:
            return
        if ethertype == eth.ETH_TYPE_ARP:
            self.arp_cache.feed_arp(ip_payload)
            return
        if ethertype != eth.ETH_TYPE_IPV4:
            # IPv6 path is future work.
            return
        try:
            iphdr, l4 = ipv4.parse_ipv4(ip_payload)
        except ValueError:
            return
        if iphdr.proto != ipv4.PROTO_TCP:
            return
        try:
            seg = tcp_segment.parse_tcp_segment(l4)
        except ValueError:
            return
        src_ip = iphdr.src_str
        dst_ip = iphdr.dst_str
        if dst_ip != self.local_ip:
            return
        # Filter to our connection.  For a connected state, use the
        # FourTuple; for LISTEN, accept whichever peer sends to our
        # local port.
        if self.state.state in ("LISTEN", "CLOSED") and self.ft is None:
            if seg.dst_port != self.state.local_port:
                return
        elif self.state.state == "LISTEN" and self.ft is not None:
            # Lock to expected peer.
            if not match_inbound(seg, src_ip, dst_ip, self.ft):
                return
        else:
            if self.ft is None or not match_inbound(seg, src_ip, dst_ip, self.ft):
                return
        accepted = self.state.on_segment(seg, src_ip)
        if accepted and self.ft is None:
            # LISTEN just bound to this peer; record the FourTuple.
            self.ft = FourTuple(
                self.local_ip, self.state.local_port,
                src_ip, seg.src_port)

    def flush_outbox(self):
        """Wrap each queued TcpSegment in IP+link headers and inject."""
        if self.state is None:
            return
        while self.state.outbox:
            seg = self.state.outbox.pop(0)
            dst_ip = self.state.remote_ip
            if dst_ip is None:
                # Should not happen in any reachable state, but defend.
                continue
            # Build TCP wire bytes (with checksum).
            tcp_bytes = tcp_segment.pack_tcp_segment(
                seg, self.local_ip, dst_ip, ipv6=False)
            ip_bytes = ipv4.pack_ipv4(
                self.local_ip, dst_ip, ipv4.PROTO_TCP, tcp_bytes)
            # Link layer.
            if self.datalink == 1:  # DLT_EN10MB
                dst_mac = self.peer_mac or self.arp_cache.get(dst_ip) or eth.MAC_BROADCAST
                src_mac = self.local_mac or eth.MAC_ZERO
                frame = eth.wrap_link_layer(
                    self.datalink, eth.ETH_TYPE_IPV4,
                    dst_mac, src_mac, ip_bytes)
            else:
                # DLT_NULL / DLT_LOOP
                frame = eth.wrap_link_layer(
                    self.datalink, eth.ETH_TYPE_IPV4, None, None, ip_bytes)
            try:
                self.backend.send(frame)
            except Exception as exc:
                print(fstr("pcap conn: send error {0}", (exc,)))

    # --- Retransmit loop ------------------------------------------------

    async def retx_loop(self):
        """Periodically check if the oldest un-acked block needs a
        retransmit.  Uses the simplest possible RTO policy -- if we've
        had unacked data for >250ms, resend it once."""
        try:
            while True:
                if self.state is None or self.state.is_closed():
                    return
                await asyncio.sleep(0.25)
                if self.state.have_unacked and self.state.unacked_data:
                    # Re-emit the unacked data as a fresh ACK+PSH segment
                    # with seq = unacked_seq (NOT snd_nxt, which has
                    # advanced past it).
                    snap_seq = self.state.unacked_seq
                    retx = tcp_segment.TcpSegment(
                        src_port=self.state.local_port,
                        dst_port=self.state.remote_port,
                        seq=snap_seq,
                        ack=self.state.rcv_nxt,
                        flags=tcp_segment.FLAG_ACK | tcp_segment.FLAG_PSH,
                        window=self.state.rcv_wnd,
                        payload=self.state.unacked_data,
                    )
                    self.state.outbox.append(retx)
                    self.flush_outbox()
        except asyncio.CancelledError:
            return

    # --- Pipe-compatible API -------------------------------------------

    @property
    def is_open(self):
        return self.state is not None and self.state.is_established()

    async def wait_established(self, timeout=10.0):
        """Block until the handshake completes or timeout fires."""
        try:
            await asyncio.wait_for(self.established_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            raise ConnectionError2("handshake timeout after {0}s".format(timeout))
        if self.state.aborted:
            raise ConnectionError2(self.state.abort_reason or "aborted")

    async def send(self, data):
        if self.state is None:
            raise ConnectionError2("send before start")
        if self.state.aborted:
            raise ConnectionError2(self.state.abort_reason)
        self.state.write(data)
        self.flush_outbox()
        return len(data)

    async def recv(self, n=4096, timeout=None):
        """Pull up to n bytes from the receive buffer.  Blocks until at
        least one byte is available, or returns b"" on close."""
        if self.state is None:
            raise ConnectionError2("recv before start")
        while True:
            if self.state.read_buf:
                return self.state.pop_read(n)
            if self.state.is_closed() or self.state.fin_received:
                # Return any final bytes then b"".
                if self.state.read_buf:
                    return self.state.pop_read(n)
                return b""
            if self.state.aborted:
                raise ConnectionError2(self.state.abort_reason)
            fut = self.loop.create_future()
            self.read_waiters.append(fut)
            try:
                if timeout is None:
                    await fut
                else:
                    await asyncio.wait_for(fut, timeout=timeout)
            except asyncio.TimeoutError:
                if fut in self.read_waiters:
                    self.read_waiters.remove(fut)
                raise

    def wake_readers(self):
        waiters, self.read_waiters = self.read_waiters, []
        for w in waiters:
            if not w.done():
                w.set_result(None)

    async def close(self):
        if self.state is None:
            return
        self.state.close()
        self.flush_outbox()
        # Give the FIN dance a moment to complete.
        try:
            await asyncio.wait_for(self.closed_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        # Tear down loops / reader.
        if self.driver_task is not None:
            self.driver_task.cancel()
            self.driver_task = None
        if self.retx_task is not None:
            self.retx_task.cancel()
            self.retx_task = None
        if self.owns_reader and self.reader is not None:
            self.reader.stop()
            self.reader = None
