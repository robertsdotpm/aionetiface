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
from typing import Any, Optional, Tuple
from ..vendor.ntp_client import NTPClient
from ..net.net_defs import UDP, IP4, IP6
from .utils import log, log_exception, async_test, fstr
from ..servers import get_infra


NTP_RETRY = 2
NTP_TIMEOUT = 2


async def get_ntp(
    af: int, interface: Any, server: Optional[Any] = None, retry: int = NTP_RETRY
) -> Optional[float]:
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
    af: int, nic: Any, dest: Tuple[str, int], retry: int = NTP_RETRY
) -> Optional[Tuple[float, float, float]]:
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
        interface: Any,
        ntp: float = 0,
        ntp_addr: Optional[str] = None,
    ) -> None:
        self.start_time = time.monotonic()
        self.interface = interface
        self.ntp = ntp
        self.offset = 0
        # Whether time() is backed by real NTP or fell back to system clock.
        self._ntp_loaded = bool(ntp)
        # When set ("host" or "host:port"), start() probes only this address
        # instead of the get_infra() pool.  Used to point peers at a LAN NTP
        # source for tight cross-machine sync (internet pool RTT 50-100 ms
        # gives +/- 50 ms accuracy which is too loose for tcp_punch
        # simultaneous-open on the LAN test bench).
        self.ntp_addr = ntp_addr

    def advance(self, n: float) -> None:
        """Shift the clock forward (or backward) by n seconds."""
        self.offset += n

    async def start(self) -> "SysClock":
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
            # Pick the lowest-RTT probe -- that's the sample with the
            # smallest one-way uncertainty, so its corrected NTP is the
            # most accurate.  Taking the first-arriving sample (old
            # behaviour) was racy: two peers each grabbed whichever NTP
            # server happened to answer fastest from their network path,
            # ending up with seeds that disagreed by 30-100 ms.
            corrected_ntp, best_rtt, monotonic_at_sample = min(
                successes, key=lambda r: r[1],
            )
            self.ntp = corrected_ntp
            # Re-pair start_time with the moment the sample was taken.
            # __init__ set start_time before the probes ran, so leaving
            # it would over-count elapsed by the probe duration.
            self.start_time = monotonic_at_sample
            self._ntp_loaded = True
            log(fstr(
                "SysClock.start: ntp={0} wall={1} delta={2}s rtt={3}ms "
                "({4} samples agreed)",
                (
                    int(self.ntp), int(wall_at_call),
                    int(wall_at_call - self.ntp), int(best_rtt * 1000),
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

    def _use_system_clock(self) -> None:
        """Seed self.ntp from the local system clock.

        Only used when the caller passes ntp=time.time() into
        __init__ explicitly to opt out of NTP. start() no longer
        falls back to this silently -- a missing NTP synchronisation
        is now a loud RuntimeError because silent fallback was
        masking real cross-machine clock-drift bugs.
        """
        self.ntp = time.time()
        self._ntp_loaded = False  # signal that this is not NTP-accurate

    def __await__(self) -> Any:
        return self.start().__await__()

    def time(self) -> float:
        """
        Return the best available timestamp.

        If NTP loaded successfully this is NTP-accurate.
        If NTP failed we fell back to the system clock at construction time,
        which advances correctly via the monotonic elapsed counter.
        Either way this never raises.
        """
        if not self.ntp:
            # start() was never called — seed from system clock right now.
            self._use_system_clock()

        elapsed = max(time.monotonic() - self.start_time, 0)
        return self.ntp + elapsed + self.offset


async def test_clock_skew() -> None:  # pragma: no cover
    from p2pd.nic.interface import Interface

    interface = await Interface()

    print("loaded")
    s = await SysClock(interface=interface)
    print(s.time())
    time.sleep(1)
    print(s.time())

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
