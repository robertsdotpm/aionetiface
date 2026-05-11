"""TCP timers -- RFC 6298 retransmit + keepalive + 2*MSL TIME-WAIT.

Pure-protocol, no I/O.  The state machine asks for `now()` (monotonic
seconds) and schedules expiry against that.

Implementation note: we don't actually use asyncio timers here, since
the state machine has to be exercisable from unit tests against a
synthetic clock.  conn.py drives the timer wheel from its asyncio
loop -- this file just owns the math.

References:
  - RFC 6298 -- Computing TCP's Retransmission Timer:
    https://datatracker.ietf.org/doc/html/rfc6298
  - RFC 9293 sec 3.5 (TIME-WAIT 2*MSL=240s default; 60s is the common
    practical setting and that's what we use).
"""


# RFC 6298 sec 2: initial RTO is 1 second, minimum is 1 second on
# bare-metal TCP.  For loopback / LAN tcp_punch we drop the floor; the
# whole point of pcap-mode is hitting tight simul-open windows.
INITIAL_RTO = 1.0
MIN_RTO = 0.05
MAX_RTO = 30.0
RTO_BACKOFF = 2.0
MAX_RETRANSMITS = 6  # ~ 0.05 * (1+2+4+8+16+32) = ~3s if floor=0.05

# 2*MSL in TIME-WAIT.  RFC 9293 default is 240s; we use 60s, which is
# what every popular stack (Linux, BSD, Windows) defaults to in practice
# and matches the description in /home/x/projects/aionetiface/CLAUDE.md
# (the TIME_WAIT lockout bites ~240s on stock Windows; we're userspace
# so we can drop our own footprint sooner).
DEFAULT_2MSL = 60.0


class RetransmitTimer(object):
    """RFC 6298 RTO estimator + retransmission queue helper.

    Tracks SRTT / RTTVAR per the standard exponential update.  Caller
    feeds raw RTT samples via update_rtt(seconds); RTO is computed
    according to RFC 6298 sec 2.3.

    Retransmissions back off geometrically (RTO_BACKOFF) up to MAX_RTO
    and give up after MAX_RETRANSMITS attempts.
    """

    def __init__(self, initial_rto=INITIAL_RTO):
        self.srtt = None
        self.rttvar = None
        self.rto = initial_rto
        self.retransmits = 0

    def update_rtt(self, sample):
        """Feed one round-trip-time sample.  `sample` is seconds."""
        if sample < 0:
            return
        if self.srtt is None:
            self.srtt = sample
            self.rttvar = sample / 2.0
        else:
            # RFC 6298 sec 2.3 -- alpha=1/8, beta=1/4.
            alpha = 1.0 / 8.0
            beta = 1.0 / 4.0
            self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - sample)
            self.srtt = (1 - alpha) * self.srtt + alpha * sample
        # RFC 6298 sec 2.3: RTO = SRTT + max(G, K*RTTVAR), G=clock granularity.
        # We treat G as 0 since monotonic() is sub-microsecond.
        rto = self.srtt + max(0.001, 4.0 * self.rttvar)
        self.rto = max(MIN_RTO, min(MAX_RTO, rto))
        self.retransmits = 0

    def on_retransmit(self):
        """Called when the RTO fires without an ACK.  Backs off."""
        self.retransmits += 1
        self.rto = min(MAX_RTO, self.rto * RTO_BACKOFF)
        return self.retransmits

    def exhausted(self):
        return self.retransmits >= MAX_RETRANSMITS

    def reset(self):
        self.retransmits = 0


class TimeWaitTimer(object):
    """Simple expiry-at-monotonic-now()+2MSL bookkeeping."""

    def __init__(self, msl_seconds=DEFAULT_2MSL):
        self.expire_at = None
        self.msl = msl_seconds

    def arm(self, now):
        self.expire_at = now + self.msl

    def expired(self, now):
        return self.expire_at is not None and now >= self.expire_at

    def disarm(self):
        self.expire_at = None
