"""
Given an NTP accurate time, this module computes an
approximation of how far off the system clock is
from the NTP time (clock skew.) The algorithm was
taken from gtk-gnutella.

https://github.com/gtk-gnutella/gtk-gnutella/
blob/devel/src/core/clock.c

Original Python version by... myself! Now with async.

This code asks for many NTP readings which are slow.
It will probably be necessary to initalize this in
an create_task that sets related objects when done.
It also doesn't support the Interface object or
Address hence it defaults to the default route.

https://datatracker.ietf.org/doc/html/rfc5905#section-6
"""

import asyncio
import time
from ..vendor.ntp_client import NTPClient
from ..net.net_defs import UDP, IP4, IP6
from .utils import log, log_exception, async_test, fstr
from ..servers import get_infra


NTP_RETRY = 2
NTP_TIMEOUT = 2


def marzullo_intersection(intervals):
    """Find the smallest interval that intersects the maximum number of input intervals.

    Each input interval is a (lo, hi) tuple representing the uncertainty
    bounds on a single NTP probe (typically [corrected_ntp - rtt/2,
    corrected_ntp + rtt/2]). Marzullo's algorithm returns the
    "truth-clique" interval: the time-range over which the largest set
    of probes agree. Center is the best estimate; half-width is the
    bounded uncertainty on that estimate.

    Returns (lo, hi) or None for an empty input.

    See M. Marzullo, "Maintaining the Time in a Distributed System",
    Stanford PhD thesis 1983; also RFC 5905 5.3 (NTP intersection).
    """
    if not intervals:
        return None

    # Event list: open at lo (+1), close at hi (-1).  At equal time the
    # +1 must fire before -1 so a zero-width interval (lo == hi) still
    # registers as a sample.
    events = []
    for lo, hi in intervals:
        events.append((lo, +1))
        events.append((hi, -1))
    events.sort(key=lambda e: (e[0], -e[1]))

    count = 0
    max_count = 0
    best_lo = None
    best_hi = None
    cur_lo = None
    for t, delta in events:
        count += delta
        if delta > 0:
            # Opening edge.  New peak resets the current best.
            if count > max_count:
                max_count = count
                cur_lo = t
                best_lo = None
                best_hi = None
            elif count == max_count and cur_lo is None:
                cur_lo = t
        else:
            # Closing edge.  If we held the peak from cur_lo until now,
            # this is a candidate truth interval; keep the narrowest.
            if cur_lo is not None and count == max_count - 1:
                if best_lo is None or (t - cur_lo) < (best_hi - best_lo):
                    best_lo = cur_lo
                    best_hi = t
                cur_lo = None

    if best_lo is None:
        # Single-sample edge case where the sweep doesn't close into a
        # truth region; fall back to the union of all intervals.
        all_los = [lo for lo, _ in intervals]
        all_his = [hi for _, hi in intervals]
        return (min(all_los), max(all_his))
    return (best_lo, best_hi)


async def get_ntp(
    af, interface, server=None, retry=NTP_RETRY
):
    if server is None:
        groups = get_infra(af, UDP, "NTP", no=1)
        if not groups:
            raise OSError("Can't find compatible NTP server.")
        server = groups[0][0]

    dest = (server["ip"], server["port"])
    try:
        for _ in range(retry):
            client = NTPClient(af, interface)
            response = await client.request(dest, version=3)
            if response is not None:
                return response.tx_time
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
    return None


async def get_ntp_from_dest(
    af, nic, dest, retry=NTP_RETRY
):
    """Probe an NTP server and return (corrected_ntp, rtt, monotonic_at_sample).

    Standard NTP four-timestamp formula (RFC 5905 6) gives offset = the gap
    between server clock and client clock, with the network round-trip
    cancelled out by the (T2-T1)+(T3-T4) symmetry trick.  Returning the raw
    `tx_time` (T3) was wrong: it's the server's clock at moment-of-send,
    already RTT/2 stale by the time the response lands here, and that stale
    value is different per probe path (different one-way latencies).  Two
    machines that each picked the *first-arriving* of N concurrent probes
    therefore ended up with NTP seeds that disagreed by 30-100 ms even
    though both polled the same servers -- which is what was breaking the
    BSD<->BSD tcp_punch simultaneous open.

    Returning rtt lets SysClock prefer the lowest-RTT (most accurate)
    sample.  Returning monotonic_at_sample lets SysClock pair the NTP
    value with the moment it was current, so `time()` later == the NTP
    sample plus monotonic elapsed since the sample (no probe duration
    over-count).
    """
    try:
        for _ in range(retry):
            client = NTPClient(af, nic)
            response = await client.request(dest, version=3)
            if response is None:
                continue

            monotonic_at_sample = time.monotonic()
            corrected_ntp = response.dest_time + response.offset
            rtt = response.delay
            return (corrected_ntp, rtt, monotonic_at_sample)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        return None


class SysClock:
    """NTP-backed clock that tracks skew between the system clock and true network time."""
    def __init__(
        self,
        interface,
        ntp=0,
        ntp_addr=None,
    ):
        self.start_time = time.monotonic()
        self.interface = interface
        self.ntp = ntp
        self.offset = 0
        # Whether time() is backed by real NTP or fell back to system clock.
        self.ntp_loaded = bool(ntp)
        # Half-width of the Marzullo truth-clique interval; the bounded
        # uncertainty on self.ntp at start_time.  0.0 means "unknown"
        # (wall-clock seed, or single-sample fallback).  Downstream
        # consumers (e.g. tcp_punch bucket sizing) can read this to
        # tighten/widen their tolerance dynamically instead of relying
        # on a static MAX_CLOCK_ERROR constant.
        self.uncertainty = 0.0
        # When set ("host" or "host:port"), start() probes only this address
        # instead of the get_infra() pool.  Used to point peers at a LAN NTP
        # source for tight cross-machine sync (internet pool RTT 50-100 ms
        # gives +/- 50 ms accuracy which is too loose for tcp_punch
        # simultaneous-open on the LAN test bench).
        self.ntp_addr = ntp_addr

    def advance(self, n):
        """Shift the clock forward (or backward) by n seconds."""
        self.offset += n

    async def start(self):
        if self.ntp:
            return self

        # Build a flat list of (af, dest) probe pairs from infra, up to 6 per AF.
        # When ntp_addr is set, probe only that single address (LAN-NTP override).
        probes = []
        if self.ntp_addr:
            host, _, port_s = self.ntp_addr.partition(":")
            port = int(port_s) if port_s else 123
            af = IP6 if ":" in host else IP4
            probes.append((af, (host, port)))
        else:
            for af in self.interface.supported():
                groups = get_infra(af, UDP, "NTP", no=6)
                for group in groups:
                    s = group[0]
                    probes.append((af, (s["ip"], s["port"])))

        if not probes:
            raise RuntimeError(
                "SysClock.start: no NTP servers available for supported AFs. "
                "Cross-machine protocol correctness depends on a synchronised "
                "clock; refusing to silently fall back to wall clock which on "
                "old VMs (XP/Vista BIOS drift) routinely runs hours off and "
                "causes signal-channel TTL drops bidirectionally. Either fix "
                "the NIC's AF support, configure local NTP, or call "
                "SysClock(ntp=time.time()) explicitly to opt into wall-clock."
            )

        # Fire all probes concurrently so slow or dead servers don't block
        # the fast ones.  First non-None result wins.
        results = await asyncio.gather(
            *[get_ntp_from_dest(af, self.interface, dest) for af, dest in probes],
            return_exceptions=True,
        )

        wall_at_call = time.time()
        successes = [r for r in results if not isinstance(r, Exception) and r]
        log(fstr(
            "SysClock.start: probes={0} successes={1} wall_at_call={2}",
            (len(probes), len(successes), int(wall_at_call)),
        ))
        if successes:
            # Marzullo intersection across ALL successful probes.  Each
            # sample defines a [ntp - rtt/2, ntp + rtt/2] candidate
            # interval (RFC 5905 5.3); the algorithm finds the smallest
            # range that intersects the largest set of those intervals.
            # Center is the best NTP estimate; half-width is the bounded
            # uncertainty.  Replaces the old min(rtt) selector which
            # discarded N-1 of N healthy samples and offered no
            # uncertainty bound to downstream consumers.
            ref_mono = max(r[2] for r in successes)
            intervals = []
            for ntp_i, rtt_i, mono_i in successes:
                # Project each sample's NTP value to the common reference
                # monotonic moment so all intervals share a coordinate
                # system.  Without this an early sample and a late
                # sample would not overlap even though both observed
                # the same true network time.
                projected = ntp_i + (ref_mono - mono_i)
                half = rtt_i / 2.0
                intervals.append((projected - half, projected + half))

            truth_lo, truth_hi = marzullo_intersection(intervals)
            corrected_ntp = (truth_lo + truth_hi) / 2.0
            uncertainty = (truth_hi - truth_lo) / 2.0

            self.ntp = corrected_ntp
            self.uncertainty = uncertainty
            # Re-pair start_time with the reference moment so time()
            # later adds only the real elapsed since that moment.
            self.start_time = ref_mono
            self.ntp_loaded = True
            log(fstr(
                "SysClock.start: ntp={0} wall={1} delta={2}s "
                "uncertainty={3}ms ({4} samples; Marzullo)",
                (
                    int(self.ntp), int(wall_at_call),
                    int(wall_at_call - self.ntp),
                    int(uncertainty * 1000),
                    len(successes),
                ),
            ))
            return self

        # Every NTP probe failed (network down, UDP/123 firewall,
        # all NTP servers unreachable). We can't silently fall back to
        # wall clock here: cross-machine protocol correctness depends
        # on a synchronised clock, and XP/Vista BIOS drift means the
        # local wall clock is routinely 11+ hours off, which silently
        # breaks signal-channel TTL checks bidirectionally with peers.
        # Surface the failure loudly so the operator sees it instead
        # of debugging mystery NO_ECHOes for hours.
        raise RuntimeError(
            "SysClock.start: all NTP probes failed (network down, UDP/123 "
            "firewall, or all NTP servers unreachable). Refusing to silently "
            "fall back to wall clock -- on old VMs that wall clock can be "
            "hours off and corrupts the signal channel. Fix NTP "
            "reachability or call SysClock(ntp=time.time()) to opt into "
            "wall-clock explicitly."
        )

    def use_system_clock(self):
        """Seed self.ntp from the local system clock.

        Only used when the caller passes ntp=time.time() into
        __init__ explicitly to opt out of NTP. start() no longer
        falls back to this silently -- a missing NTP synchronisation
        is now a loud RuntimeError because silent fallback was
        masking real cross-machine clock-drift bugs.
        """
        self.ntp = time.time()
        self.ntp_loaded = False  # signal that this is not NTP-accurate

    def __await__(self):
        return self.start().__await__()

    def time(self):
        """
        Return the best available timestamp.

        If NTP loaded successfully this is NTP-accurate.
        If NTP failed we fell back to the system clock at construction time,
        which advances correctly via the monotonic elapsed counter.
        Either way this never raises.
        """
        if not self.ntp:
            # start() was never called — seed from system clock right now.
            self.use_system_clock()

        elapsed = max(time.monotonic() - self.start_time, 0)
        return self.ntp + elapsed + self.offset


async def test_clock_skew():  # pragma: no cover
    from warpgate.nic.interface import Interface

    interface = await Interface()

    s = await SysClock(interface=interface)
    time.sleep(1)

    return


if __name__ == "__main__":
    # sys_clock = SysClock()
    # print(sys_clock.clock_skew)
    async_test(test_clock_skew)

    # print(get_ntp())
    # print(get_ntp())

    """
    print(sys_clock.time())
    print()
    print(get_ntp())
    print(sys_clock.time())
    print()
    print(get_ntp())
    print(sys_clock.time())
    """
