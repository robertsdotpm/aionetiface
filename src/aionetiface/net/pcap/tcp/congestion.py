"""Minimum congestion-control stub.

A real NewReno (RFC 5681) cwnd / ssthresh implementation is overkill
for tcp_punch -- the punch handshake is a couple of segments and the
subsequent payload exchange is tiny.  But we still need *something* so
the sender doesn't infinitely flood the receiver.

What this gives us:
  - Initial window (IW) of 4 segments per RFC 6928 minimums.
  - Linear cwnd growth on each ACK (no ssthresh distinction).
  - Halve cwnd on retransmit (the simplest sane reaction).

If we ever need real congestion control (high-throughput pcap path),
swap this class out -- conn.py only depends on the three public
methods below.

References:
  - RFC 5681 -- TCP Congestion Control:
    https://datatracker.ietf.org/doc/html/rfc5681
  - RFC 6928 -- Increasing TCP's Initial Window:
    https://datatracker.ietf.org/doc/html/rfc6928
"""


class Congestion(object):
    """Mini congestion controller.  Units are segments, not bytes."""

    def __init__(self, mss=1460, initial_cwnd_segments=4, cap_segments=64):
        self.mss = int(mss)
        self.cwnd_segments = int(initial_cwnd_segments)
        self.cap = int(cap_segments)

    def cwnd_bytes(self):
        """Maximum un-acked bytes we're allowed to have on the wire."""
        return self.cwnd_segments * self.mss

    def on_ack(self):
        """One in-window ACK arrived; nudge cwnd up by one segment."""
        if self.cwnd_segments < self.cap:
            self.cwnd_segments += 1

    def on_retransmit(self):
        """RTO fired -- back off."""
        self.cwnd_segments = max(1, self.cwnd_segments // 2)
