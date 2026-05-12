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
from ..ip.next_hop import resolve_next_hop_mac, resolve_local_mac
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
                 reader=None, local_subnet=None):
        self.backend = backend
        self.local_ip = local_ip
        self.local_mac = (
            eth.parse_mac(local_mac) if isinstance(local_mac, str)
            else local_mac
        )
        # If the caller didn't supply our NIC's MAC, resolve it from the
        # host OS once.  Frames with src_mac=00 are silently dropped on
        # most paths (MAC-learning switches, consumer-router egress
        # filters, some vSwitch policies), so the kernel-provided value
        # is load-bearing -- the pcap path bypasses the kernel's normal
        # L2 framing so we have to fill this in ourselves.
        if self.local_mac is None and local_ip is not None:
            try:
                resolved = resolve_local_mac(local_ip)
            except Exception as exc:
                resolved = None
            if resolved is not None:
                self.local_mac = resolved
            else:
                pass
        # Optional dotted-quad subnet mask for the NIC behind local_ip.
        # When supplied, the next-hop resolver can distinguish same-LAN
        # destinations (resolve dst_ip MAC directly) from off-LAN ones
        # (resolve default-gateway MAC).  When None, the resolver falls
        # back to the OS-route default-gateway path for any destination
        # not already in the inbound-learned ArpCache, which is correct
        # for cross-NAT flows but slightly wasteful for same-LAN.
        self.local_subnet = local_subnet
        self.loop = loop or asyncio.get_event_loop()
        self.reader = reader  # optional pre-created PcapReader
        self.owns_reader = reader is None

        self.state = None  # TcpState instance once configured
        self.ft = None     # FourTuple
        self.peer_mac = None
        self.arp_cache = eth.ArpCache()
        self.datalink = backend.datalink()
        # Cache the OS next-hop MAC the first time flush_outbox needs
        # it -- avoids re-spawning `arp -a` / re-reading /proc on every
        # outbound segment.  None means "not resolved yet"; the empty
        # bytes sentinel b"" means "tried and failed, fall back to
        # broadcast next time too".
        self.next_hop_mac_cache = None

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
                    pass
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
        # On DLT_EN10MB datalinks we ALSO want the Ethernet source MAC so
        # we can learn the peer's MAC from any inbound IPv4 packet they
        # send us, not just from ARP -- the simul-open path (XP bypass)
        # never issues a request/reply pair because both ends are already
        # talking via a NAT-derived 4-tuple, so a SYN that arrives here
        # is the first sighting of the peer's L2 address.  Without this
        # we'd emit our SYN-ACK/ACK with dst_mac=BROADCAST which the
        # peer's stack typically tolerates but some link-layer paths
        # (Linux veth carrier checks, certain offload paths) silently
        # discard.
        src_mac_from_eth = None
        try:
            if self.datalink == 1:  # DLT_EN10MB
                _, src_mac_from_eth, ethertype, ip_payload = eth.parse_eth_frame(frame)
            else:
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
        # Learn peer MAC from this TCP frame's L2 header (DLT_EN10MB only).
        # Skips zero / broadcast sources (some pcap stacks inject those as
        # the L2 source for unknown peers; treating those as authoritative
        # would poison the cache).
        if src_mac_from_eth is not None and src_mac_from_eth not in (
            eth.MAC_ZERO, eth.MAC_BROADCAST,
        ):
            self.arp_cache.put(src_ip, src_mac_from_eth)
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

    def resolve_dst_mac(self, dst_ip):
        """Pick the L2 destination MAC for an outbound IPv4 frame.

        Priority:
            1. peer_mac explicitly set by the caller (start_active
               passed remote_mac=) -- absolute trust, the caller knows
               better than we do.
            2. ArpCache hit on dst_ip from inbound-frame learning --
               this covers the same-L2 path (linux veth tests, two
               hosts on one switch) where the peer MAC arrives on the
               wire before we ever transmit.
            3. OS next-hop resolution via resolve_next_hop_mac --
               reads the host's existing ARP cache + route table.
               This is the cross-NAT case: there is no peer MAC
               anywhere on our wire, so we have to send to the gateway
               MAC and let the gateway do its NAT-and-forward job.
            4. Broadcast as a last-ditch fallback, matching the
               pre-fix behaviour.  Some same-LAN-flooded paths still
               deliver in this mode.

        The OS-next-hop result is cached on the Connection so we don't
        re-spawn `arp -a` on every outbound segment.  The cache is
        invalidated on close (Connection goes away with the instance).
        """
        if self.peer_mac is not None:
            return self.peer_mac
        learned = self.arp_cache.get(dst_ip)
        if learned is not None and learned not in (eth.MAC_ZERO, eth.MAC_BROADCAST):
            return learned
        if self.next_hop_mac_cache is None:
            try:
                resolved = resolve_next_hop_mac(
                    dst_ip,
                    local_ip=self.local_ip,
                    local_subnet=self.local_subnet,
                    arp_cache=self.arp_cache,
                )
            except Exception as exc:
                # Helper is read-only and defensive but we still don't
                # want a parse failure to nuke the whole TCP flow.
                resolved = None
            if resolved is None:
                # Sentinel: we've tried and failed once, don't retry on
                # every flush.  A future inbound frame may populate the
                # ArpCache and short-circuit branch (2) above.
                self.next_hop_mac_cache = b""
            else:
                self.next_hop_mac_cache = resolved
        if self.next_hop_mac_cache and self.next_hop_mac_cache != b"":
            return self.next_hop_mac_cache
        return eth.MAC_BROADCAST

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
                dst_mac = self.resolve_dst_mac(dst_ip)
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
                pass

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
