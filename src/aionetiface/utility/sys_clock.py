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

import time
import random
from decimal import Decimal as Dec
from ..net.address import *
from ..vendor.ntp_client import NTPClient
from ..settings import *
from ..nic.interface import *
from ..servers import get_infra

NTP_RETRY = 2
NTP_TIMEOUT = 2

async def get_ntp(af, interface, server=None, retry=NTP_RETRY):
    if server is None:
        groups = get_infra(af, UDP, "NTP", no=1)
        if not groups:
            raise Exception("Can't find compatible NTP server.")
        server = groups[0][0]

    dest = (server["ip"], server["port"])
    try:
        for _ in range(retry):
            client = NTPClient(af, interface)
            response = await client.request(dest, version=3)
            if response is not None:
                return response.tx_time
    except asyncio.CancelledError:
        raise
    except Exception:
        log_exception()
    return None

async def get_ntp_from_dest(af, nic, dest, retry=NTP_RETRY):
    # The NTP client uses UDP so retry on failure.
    try:
        for _ in range(retry):
            client = NTPClient(af, nic)
            response = await client.request(
                dest,
                version=3
            )
            if response is None:
                continue

            ntp = response.tx_time
            return ntp
    except asyncio.CancelledError:
        raise
    except Exception as e:
        log_exception()
        return None


class SysClock:
    def __init__(self, interface, ntp=0):
        self.start_time = time.monotonic()
        self.interface = interface
        self.ntp = ntp
        self.offset = 0
        # Whether time() is backed by real NTP or fell back to system clock.
        self._ntp_loaded = bool(ntp)

    def advance(self, n):
        self.offset += n

    async def start(self):
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
            log("SysClock: no NTP servers available for supported AFs; using system clock.")
            self._use_system_clock()
            return self

        # Fire all probes concurrently so slow or dead servers don't block
        # the fast ones.  First non-None result wins.
        results = await asyncio.gather(
            *[get_ntp_from_dest(af, self.interface, dest) for af, dest in probes],
            return_exceptions=True
        )

        for result in results:
            if isinstance(result, Exception):
                continue
            if result:
                self.ntp = result
                self._ntp_loaded = True
                return self

        # All NTP probes failed (network down, firewall on UDP 123, etc.).
        # Fall back to the system clock so time() never raises.
        log("SysClock: all NTP probes failed; falling back to system clock.")
        self._use_system_clock()
        return self

    def _use_system_clock(self):
        """Seed self.ntp from the local system clock as a last resort."""
        self.ntp = time.time()
        self._ntp_loaded = False  # signal that this is not NTP-accurate

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
            self._use_system_clock()

        elapsed = max(time.monotonic() - self.start_time, 0)
        return self.ntp + elapsed + self.offset

async def test_clock_skew(): # pragma: no cover
    from p2pd.nic.interface import Interface
    interface = await Interface()


    print("loaded")
    s = await SysClock(interface=interface)
    print(s.time())
    time.sleep(1)
    print(s.time())


    return

if __name__ == "__main__":
    #sys_clock = SysClock()
    #print(sys_clock.clock_skew)
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
