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
from ..net.net_defs import UDP
from .utils import log, log_exception, async_test
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
) -> Optional[float]:
    # The NTP client uses UDP so retry on failure.
    try:
        for _ in range(retry):
            client = NTPClient(af, nic)
            response = await client.request(dest, version=3)
            if response is None:
                continue

            ntp = response.tx_time
            return ntp
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        return None


class SysClock:
    """NTP-backed clock that tracks skew between the system clock and true network time."""
    def __init__(self, interface: Any, ntp: float = 0) -> None:
        self.start_time = time.monotonic()
        self.interface = interface
        self.ntp = ntp
        self.offset = 0
        # Whether time() is backed by real NTP or fell back to system clock.
        self._ntp_loaded = bool(ntp)

    def advance(self, n: float) -> None:
        """Shift the clock forward (or backward) by n seconds."""
        self.offset += n

    async def start(self) -> "SysClock":
        if self.ntp:
            return self

        # Build a flat list of (af, dest) probe pairs from infra, up to 6 per AF.
        probes = []
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

        for result in results:
            if isinstance(result, Exception):
                continue
            if result:
                self.ntp = result
                self._ntp_loaded = True
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
