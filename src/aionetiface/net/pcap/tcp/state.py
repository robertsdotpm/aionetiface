"""TCP state machine (RFC 9293 sec 3.6).

Pure state-transition logic.  Holds no sockets, no Backend, no timers.
The conn.py wrapper drives feed_segment()/send_segment() against this
class and supplies the I/O + clock.

States:
    CLOSED          -- nothing happening
    LISTEN          -- waiting for an incoming SYN
    SYN_SENT        -- active opener, sent SYN, waiting for SYN+ACK
                       or (for simul-open) a SYN-without-ACK
    SYN_RECEIVED    -- got SYN, sent SYN+ACK (also: simul-open landing)
    ESTABLISHED     -- handshake done; data can flow
    FIN_WAIT_1      -- sent FIN, waiting for ACK
    FIN_WAIT_2      -- got ACK of FIN, waiting for peer FIN
    CLOSE_WAIT      -- peer sent FIN, we owe an ACK
    CLOSING         -- both sides FIN'd at once, waiting for ACK of ours
    LAST_ACK        -- after CLOSE_WAIT we sent our FIN; waiting for ACK
    TIME_WAIT       -- both sides closed; quiesce for 2*MSL then disappear

References:
  - RFC 9293 sec 3.6 (state diagram + event semantics)
  - RFC 9293 sec 3.10 (Event processing rules)

Simul-open path (the XP bypass):
    Both sides start in SYN_SENT having transmitted their own SYN.
    Each receives the *other* side's SYN -- a SYN without ACK, whose
    destination matches the SYN_SENT four-tuple.  RFC 9293 sec 3.10.7.4
    says: on SYN_SENT, if SYN arrives without ACK, move to SYN_RECEIVED
    and send SYN+ACK with our original ISS as seq.  When the
    corresponding ACK lands, move to ESTABLISHED.

    Why XP's kernel breaks this: tcpip.sys *does* implement that path,
    but it RSTs the connection ~140-180ms after ESTABLISHED for reasons
    nobody outside Microsoft has nailed down.  Our userspace stack just
    follows the RFC and stays up.
"""
import random

from .segment import (
    TcpSegment, FLAG_SYN, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_PSH,
    build_mss_option,
)


# State constants -- plain strings so they show up sanely in print/log.
CLOSED = "CLOSED"
LISTEN = "LISTEN"
SYN_SENT = "SYN_SENT"
SYN_RECEIVED = "SYN_RECEIVED"
ESTABLISHED = "ESTABLISHED"
FIN_WAIT_1 = "FIN_WAIT_1"
FIN_WAIT_2 = "FIN_WAIT_2"
CLOSE_WAIT = "CLOSE_WAIT"
CLOSING = "CLOSING"
LAST_ACK = "LAST_ACK"
TIME_WAIT = "TIME_WAIT"


def random_iss():
    """Initial Sequence Number per RFC 9293 sec 3.4.1.  We don't need
    the timestamped scheme that real stacks use; tcp_punch sessions are
    short-lived and we control both endpoints."""
    return random.randint(0, 0xffffffff)


def seq_in_window(seq, win_start, win_end):
    """Modulo-2**32 window check.  RFC 9293 sec 3.4 -- a sequence
    number `seq` is acceptable iff it lies in [win_start, win_end)
    after wrap.
    """
    win_size = (win_end - win_start) & 0xffffffff
    rel = (seq - win_start) & 0xffffffff
    return rel < win_size


class TcpState(object):
    """The state machine + the bare minimum of TCB (Transmission
    Control Block) state RFC 9293 names: SND.NXT, SND.UNA, RCV.NXT,
    SND.WND, RCV.WND.

    No I/O.  Callers in conn.py:
      - call open_active(local_port, remote_ip, remote_port) for client
      - call open_listen(local_port) for server
      - feed inbound segments via on_segment(seg) and read any outbound
        responses from self.outbox (cleared by the caller after send)
      - call write(data) to enqueue payload; segments to send appear in
        self.outbox once the state allows
      - call close() to start the FIN dance
    """

    def __init__(self, local_ip, local_port, mss=1460):
        self.local_ip = local_ip
        self.local_port = int(local_port)
        self.remote_ip = None
        self.remote_port = 0

        self.state = CLOSED

        # Send sequence variables (RFC 9293 sec 3.3.1).
        self.snd_nxt = 0       # next seq to send
        self.snd_una = 0       # oldest unacknowledged seq
        self.iss = 0           # our initial send seq
        self.snd_wnd = 65535   # peer's advertised window

        # Receive sequence variables.
        self.rcv_nxt = 0       # next seq we expect from peer
        self.irs = 0           # peer's initial seq
        self.rcv_wnd = 65535   # what we advertise

        # Output queue: list of TcpSegment to transmit.  conn.py pops
        # these in order and runs pack_tcp_segment() over each.
        self.outbox = []

        # Application receive buffer (bytes appended in arrival order).
        self.read_buf = bytearray()
        # Application send buffer (not yet been put into a segment).
        self.send_buf = bytearray()
        # In-flight payload bytes (seq -> bytes) for retransmission.
        # We only retransmit the oldest un-acked segment to keep things
        # simple; that's enough for short tcp_punch payloads.
        self.unacked_data = b""
        self.unacked_seq = 0
        # Hook for the conn.py timer wheel to ask "do I have anything
        # waiting for an ACK right now?".
        self.have_unacked = False

        # MSS we advertised in our SYN.
        self.local_mss = int(mss)
        # MSS the peer advertised; only filled in once we've seen a SYN
        # with an MSS option from them.
        self.peer_mss = int(mss)

        # Per-connection 'we're done, please reap me' flag.
        self.fin_received = False
        self.fin_sent = False

        # If the peer asked us to reset (or we reset them), this flag
        # tells conn.py to surface a hard error.
        self.aborted = False
        self.abort_reason = None

    # --- Helpers for emitting segments ----------------------------------

    def emit(self, flags, payload=b"", ack=None):
        """Push a TcpSegment for the caller to transmit.

        seq is taken from snd_nxt; ack defaults to rcv_nxt; SYN and FIN
        flags advance snd_nxt by one (sequence-consuming) per RFC 9293.
        Payload bytes advance snd_nxt by len(payload).
        """
        seg = TcpSegment(
            src_port=self.local_port,
            dst_port=self.remote_port,
            seq=self.snd_nxt,
            ack=self.rcv_nxt if ack is None else ack,
            flags=flags,
            window=self.rcv_wnd,
            payload=payload,
        )
        if flags & FLAG_SYN:
            # Advertise our MSS on SYN segments (RFC 9293 sec 3.7.1).
            seg.options = build_mss_option(self.local_mss)
        self.outbox.append(seg)
        # Advance snd_nxt for sequence-consuming flags + payload bytes.
        adv = seg.segment_length()
        self.snd_nxt = (self.snd_nxt + adv) & 0xffffffff
        if payload:
            # Track for retransmit.  Keep only the most recent un-acked
            # block; that's a deliberate simplification for short
            # tcp_punch sessions and is well-tested at this scale.
            self.unacked_data = bytes(payload)
            self.unacked_seq = (self.snd_nxt - len(payload)) & 0xffffffff
            self.have_unacked = True
        if flags & FLAG_FIN:
            self.fin_sent = True
        return seg

    def emit_rst(self, seq=None, ack=None):
        """Send a RST.  RFC 9293 sec 3.10.7 -- a RST under SYN_SENT
        carries seq=0, ack=SEG.SEQ+1; a RST under any other state with
        ACK set carries seq=SEG.ACK, ack=0."""
        flags = FLAG_RST
        if ack is not None:
            flags |= FLAG_ACK
        seg = TcpSegment(
            src_port=self.local_port,
            dst_port=self.remote_port,
            seq=self.snd_nxt if seq is None else seq,
            ack=0 if ack is None else ack,
            flags=flags,
            window=0,
        )
        self.outbox.append(seg)
        return seg

    # --- User-facing entry points ---------------------------------------

    def open_active(self, remote_ip, remote_port):
        """Client side -- start the three-way (or simul-open) handshake.

        Caller fills remote_ip / remote_port from auto_connect's
        addressing layer.  We move CLOSED -> SYN_SENT and queue the
        opening SYN."""
        if self.state != CLOSED:
            raise ValueError("open_active in non-CLOSED state {0}".format(self.state))
        self.remote_ip = remote_ip
        self.remote_port = int(remote_port)
        self.iss = random_iss()
        self.snd_nxt = self.iss
        self.snd_una = self.iss
        self.emit(FLAG_SYN)
        self.state = SYN_SENT

    def open_listen(self):
        """Server side -- enter LISTEN waiting for a SYN."""
        if self.state != CLOSED:
            raise ValueError("open_listen in non-CLOSED state {0}".format(self.state))
        self.state = LISTEN

    def open_simul(self, remote_ip, remote_port):
        """Force the simultaneous-open path: we know the peer is going
        to send a SYN too, so just transmit ours immediately rather than
        waiting in LISTEN.  This is what the tcp_punch plugin calls --
        both sides are already coordinated by the signal channel."""
        return self.open_active(remote_ip, remote_port)

    def write(self, data):
        """Application send.  Enqueues into self.send_buf; segments are
        formed and pushed to outbox once we're in a writable state."""
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("write data must be bytes")
        if self.state in (CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED):
            # Buffer for later; spec allows this.
            self.send_buf.extend(data)
            return
        if self.state != ESTABLISHED:
            raise ValueError("cannot write in state {0}".format(self.state))
        self.send_buf.extend(data)
        self.flush_send()

    def flush_send(self):
        """Form one segment from the front of send_buf, if any."""
        if not self.send_buf:
            return
        if self.have_unacked:
            # Only one outstanding block at a time -- see the comment on
            # unacked_data above.
            return
        chunk = bytes(self.send_buf[: self.peer_mss])
        del self.send_buf[: len(chunk)]
        self.emit(FLAG_ACK | FLAG_PSH, payload=chunk)

    def close(self):
        """Application close -- start the FIN dance."""
        if self.state == CLOSED or self.state == LISTEN:
            self.state = CLOSED
            return
        if self.state == SYN_SENT:
            # Connection was never established.  Just drop.
            self.state = CLOSED
            return
        if self.state == SYN_RECEIVED:
            self.emit(FLAG_FIN | FLAG_ACK)
            self.state = FIN_WAIT_1
            return
        if self.state == ESTABLISHED:
            self.emit(FLAG_FIN | FLAG_ACK)
            self.state = FIN_WAIT_1
            return
        if self.state == CLOSE_WAIT:
            self.emit(FLAG_FIN | FLAG_ACK)
            self.state = LAST_ACK
            return
        # FIN_WAIT_*, CLOSING, LAST_ACK, TIME_WAIT -- close is a no-op.

    # --- Inbound segment processing -------------------------------------

    def on_segment(self, seg, src_ip):
        """Drive the state machine with one received segment.

        Returns True if we accepted it (state may have changed), False
        if we ignored / dropped it (e.g. wrong four-tuple in LISTEN).
        """
        # Wrong four-tuple? Only LISTEN accepts arbitrary src_ip; every
        # other state is bound to a peer.
        if self.state != CLOSED and self.state != LISTEN:
            if seg.src_port != self.remote_port or src_ip != self.remote_ip:
                return False
        # RST handling per RFC 9293 sec 3.10.7.
        if seg.has_flag(FLAG_RST):
            return self.handle_rst(seg)
        # SYN-only / SYN+ACK / ACK / payload / FIN -- branch on state.
        if self.state == CLOSED:
            # Spec says respond with RST if SYN; we don't bother since
            # the peer wasn't expecting us anyway.
            return False
        if self.state == LISTEN:
            return self.on_segment_listen(seg, src_ip)
        if self.state == SYN_SENT:
            return self.on_segment_syn_sent(seg, src_ip)
        if self.state == SYN_RECEIVED:
            return self.on_segment_syn_received(seg, src_ip)
        if self.state in (ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
                          CLOSE_WAIT, CLOSING, LAST_ACK):
            return self.on_segment_established(seg)
        if self.state == TIME_WAIT:
            # Anything received in TIME_WAIT: re-ACK to handle peer
            # retransmits of FIN.
            if seg.has_flag(FLAG_FIN):
                # Re-ack peer's FIN.
                ack_seg = TcpSegment(
                    src_port=self.local_port, dst_port=self.remote_port,
                    seq=self.snd_nxt, ack=self.rcv_nxt, flags=FLAG_ACK,
                    window=self.rcv_wnd,
                )
                self.outbox.append(ack_seg)
            return True
        return False

    def handle_rst(self, seg):
        """RFC 9293 sec 3.10.7.1 -- a RST aborts the connection
        unconditionally in any synchronised state."""
        # In SYN_SENT, accept the RST only if it acks our SYN.  This
        # prevents a stray off-path RST (XP-style cross-NAT) from
        # killing us before we hear back from the peer.
        if self.state == SYN_SENT:
            if not seg.has_flag(FLAG_ACK):
                return False
            if seg.ack != ((self.iss + 1) & 0xffffffff):
                return False
        self.aborted = True
        self.abort_reason = "peer RST in state {0}".format(self.state)
        self.state = CLOSED
        return True

    def on_segment_listen(self, seg, src_ip):
        """LISTEN: only a SYN advances state."""
        if seg.has_flag(FLAG_ACK):
            # RFC: bad -- send RST with seq=seg.ack.
            self.emit_rst(seq=seg.ack)
            return False
        if not seg.has_flag(FLAG_SYN):
            return False
        # Latch the peer.
        self.remote_ip = src_ip
        self.remote_port = seg.src_port
        self.irs = seg.seq
        self.rcv_nxt = (seg.seq + 1) & 0xffffffff
        self.iss = random_iss()
        self.snd_nxt = self.iss
        self.snd_una = self.iss
        self.read_peer_mss(seg)
        # Reply SYN+ACK and advance.
        self.emit(FLAG_SYN | FLAG_ACK)
        self.state = SYN_RECEIVED
        return True

    def on_segment_syn_sent(self, seg, src_ip):
        """SYN_SENT processing -- includes the simul-open branch."""
        if seg.has_flag(FLAG_ACK):
            # ACK must acknowledge our SYN (snd_una < ack <= snd_nxt).
            if not seq_in_window(seg.ack,
                                 (self.snd_una + 1) & 0xffffffff,
                                 (self.snd_nxt + 1) & 0xffffffff):
                return False
        if not seg.has_flag(FLAG_SYN):
            return False
        # Whether or not ACK is set, the peer's SYN advances our irs.
        self.irs = seg.seq
        self.rcv_nxt = (seg.seq + 1) & 0xffffffff
        self.read_peer_mss(seg)
        if seg.has_flag(FLAG_ACK):
            # Normal three-way handshake completion.
            self.snd_una = seg.ack
            self.snd_wnd = seg.window
            # ACK the SYN+ACK and move to ESTABLISHED.
            ack_seg = TcpSegment(
                src_port=self.local_port, dst_port=self.remote_port,
                seq=self.snd_nxt, ack=self.rcv_nxt, flags=FLAG_ACK,
                window=self.rcv_wnd,
            )
            self.outbox.append(ack_seg)
            self.state = ESTABLISHED
            self.flush_send()
            return True
        # SIMUL-OPEN: SYN without ACK and the four-tuple matches our
        # outbound SYN.  RFC 9293 sec 3.10.7.4 says move to SYN_RECEIVED
        # and emit SYN+ACK with seq=ISS (i.e. retransmit our SYN, but
        # with the ACK bit set).
        ack_seg = TcpSegment(
            src_port=self.local_port, dst_port=self.remote_port,
            seq=self.iss, ack=self.rcv_nxt, flags=FLAG_SYN | FLAG_ACK,
            window=self.rcv_wnd,
            options=build_mss_option(self.local_mss),
        )
        # Note we set seq=ISS, NOT snd_nxt: snd_nxt has already advanced
        # past our original SYN, but the simul-open SYN+ACK retransmits
        # *that* SYN (with the ACK now riding on it).  snd_nxt does not
        # advance again for it.
        self.outbox.append(ack_seg)
        self.state = SYN_RECEIVED
        return True

    def on_segment_syn_received(self, seg, src_ip):
        """SYN_RECEIVED: waiting for the ACK that finishes the handshake.

        Also handles a retransmitted SYN from the peer (re-emit SYN+ACK).
        """
        if seg.has_flag(FLAG_SYN) and not seg.has_flag(FLAG_ACK):
            # Peer retransmitted their SYN.  Re-send our SYN+ACK.
            retx = TcpSegment(
                src_port=self.local_port, dst_port=self.remote_port,
                seq=self.iss, ack=self.rcv_nxt, flags=FLAG_SYN | FLAG_ACK,
                window=self.rcv_wnd,
                options=build_mss_option(self.local_mss),
            )
            self.outbox.append(retx)
            return True
        if not seg.has_flag(FLAG_ACK):
            return False
        # Must acknowledge our SYN.
        expected_ack = (self.iss + 1) & 0xffffffff
        if seg.ack != expected_ack:
            # Could be a stale segment; drop quietly.
            return False
        self.snd_una = seg.ack
        self.snd_wnd = seg.window
        self.state = ESTABLISHED
        # Process any payload that rode on the final ACK.
        if seg.payload:
            self.read_buf.extend(seg.payload)
            self.rcv_nxt = (self.rcv_nxt + len(seg.payload)) & 0xffffffff
            self.emit_pure_ack()
        if seg.has_flag(FLAG_FIN):
            self.handle_peer_fin(seg)
        self.flush_send()
        return True

    def on_segment_established(self, seg):
        """ESTABLISHED + close-related states: data + ACK + FIN handling."""
        # Acceptability test (RFC 9293 sec 3.10.7.4: receive window).
        # We accept anything that overlaps [rcv_nxt, rcv_nxt+rcv_wnd).
        seg_len = seg.segment_length()
        if seg_len > 0:
            in_window = seq_in_window(
                seg.seq, self.rcv_nxt,
                (self.rcv_nxt + max(1, self.rcv_wnd)) & 0xffffffff,
            )
            if not in_window:
                # Out-of-window: still send an ACK so the peer knows
                # where we are.
                self.emit_pure_ack()
                return False

        # ACK field updates SND.UNA / SND.WND.
        if seg.has_flag(FLAG_ACK):
            if seq_in_window(seg.ack,
                             (self.snd_una + 1) & 0xffffffff,
                             (self.snd_nxt + 1) & 0xffffffff):
                # New cumulative ACK.
                self.snd_una = seg.ack
                self.snd_wnd = seg.window
                # If the new ACK covers everything in unacked_data, clear it.
                if self.have_unacked:
                    end_seq = (self.unacked_seq + len(self.unacked_data)) & 0xffffffff
                    if seq_in_window(end_seq, self.snd_una, (self.snd_una + 1) & 0xffffffff) or end_seq == self.snd_una:
                        self.unacked_data = b""
                        self.have_unacked = False
            elif seg.ack == self.snd_una:
                # Duplicate ACK; ignore.
                pass

        # Payload?
        if seg.payload and seg.seq == self.rcv_nxt:
            self.read_buf.extend(seg.payload)
            self.rcv_nxt = (self.rcv_nxt + len(seg.payload)) & 0xffffffff
            self.emit_pure_ack()
        elif seg.payload:
            # Out-of-order payload -- we don't buffer for the simple
            # tcp_punch case.  Just ACK what we have.
            self.emit_pure_ack()

        # FIN?  Only consumes a sequence if it's in-order.
        if seg.has_flag(FLAG_FIN) and seg.seq + len(seg.payload) == self.rcv_nxt - 0:
            # The "+ len(seg.payload)" + the "==" together check that the
            # FIN's sequence is exactly rcv_nxt (the spot right after any
            # payload we just consumed).
            self.handle_peer_fin(seg)

        # State transitions on close.
        if self.state == FIN_WAIT_1 and self.fin_acked():
            if self.fin_received:
                self.state = TIME_WAIT
            else:
                self.state = FIN_WAIT_2
        if self.state == CLOSING and self.fin_acked():
            self.state = TIME_WAIT
        if self.state == LAST_ACK and self.fin_acked():
            self.state = CLOSED

        # Anything new to send from the buffer?
        if self.state == ESTABLISHED:
            self.flush_send()
        return True

    def handle_peer_fin(self, seg):
        """Process a FIN from the peer in any synchronised state."""
        if self.fin_received:
            return
        self.fin_received = True
        # FIN takes one sequence number.
        self.rcv_nxt = (self.rcv_nxt + 1) & 0xffffffff
        self.emit_pure_ack()
        if self.state == ESTABLISHED:
            self.state = CLOSE_WAIT
        elif self.state == FIN_WAIT_1:
            # If our FIN hasn't been ACKed yet, we go to CLOSING.
            if self.fin_acked():
                self.state = TIME_WAIT
            else:
                self.state = CLOSING
        elif self.state == FIN_WAIT_2:
            self.state = TIME_WAIT

    def emit_pure_ack(self):
        """Push a zero-payload ACK with current rcv_nxt."""
        ack = TcpSegment(
            src_port=self.local_port, dst_port=self.remote_port,
            seq=self.snd_nxt, ack=self.rcv_nxt, flags=FLAG_ACK,
            window=self.rcv_wnd,
        )
        self.outbox.append(ack)

    def fin_acked(self):
        """True iff our outbound FIN has been acknowledged."""
        if not self.fin_sent:
            return False
        # snd_una has advanced past the FIN's sequence number iff
        # snd_una == snd_nxt.
        return self.snd_una == self.snd_nxt

    def read_peer_mss(self, seg):
        """Extract peer's MSS option from a SYN, if present."""
        from .segment import parse_options, get_option, OPT_MSS
        if not seg.has_flag(FLAG_SYN):
            return
        opts = parse_options(seg.options)
        raw = get_option(opts, OPT_MSS)
        if raw and len(raw) == 2:
            import struct as _struct
            self.peer_mss = max(536, _struct.unpack("!H", raw)[0])

    # --- Read helpers ---------------------------------------------------

    def pop_read(self, n=None):
        """Pull up to `n` bytes from the read buffer (None == all)."""
        if n is None or n >= len(self.read_buf):
            out = bytes(self.read_buf)
            self.read_buf = bytearray()
            return out
        out = bytes(self.read_buf[:n])
        del self.read_buf[:n]
        return out

    def is_established(self):
        return self.state == ESTABLISHED

    def is_closed(self):
        return self.state == CLOSED
