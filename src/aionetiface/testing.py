"""
aionetiface.testing — shared test utilities for aionetiface and dependent repos.

Provides:
  AsyncTestCase           — IsolatedAsyncioTestCase backport for Python 3.5+
                            with ProactorEventLoop fix for Windows < 3.8 and
                            asyncio.all_tasks compat for Python < 3.7.
  FakeInterface           — interface stub presenting a single specific IP,
                            wrapping real route metadata for bind/connect ops.
  FakeInterfaceFactory    — builds a pool of FakeInterface objects from live
                            routes, falling back to probed 127.0.0.x loopback.
  probe_loopback_ips      — return which 127.0.0.x IPs are actually bindable.

Typical test pattern:

    from aionetiface.testing import AsyncTestCase, FakeInterfaceFactory, IP4, IP6

    class TestMyPlugin(AsyncTestCase):
        async def asyncSetUp(self):
            self.factory = await FakeInterfaceFactory.create()

        async def test_two_nodes(self):
            ifaces = self.factory.get(2, IP4)
            if len(ifaces) < 2:
                self.skipTest("need 2 distinct IPv4 addresses")
            ...
"""

import asyncio
import copy
import socket
import sys
import unittest
from typing import Any, List, Optional

from .net.net_defs import IP4, IP6
from .net.ip_range import IPRange
from .net.bind.bind_utils import bind_closure
from .net.bind.bind_rules import binder_async
from .nic.route.route import Route
from .nic.select_interface import list_interfaces
from .nic.interface_utils import load_interfaces
from .nic.interface import Interface


# ─────────────────────────────────────────────────────────────
# AsyncTestCase — IsolatedAsyncioTestCase backport
# ─────────────────────────────────────────────────────────────

if sys.platform == "win32" and sys.version_info < (3, 8):
    if hasattr(asyncio, "WindowsProactorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


def get_pending_tasks(loop):
    """Return pending asyncio tasks for loop, compatible with Python 3.5+."""
    if sys.version_info >= (3, 7):
        return asyncio.all_tasks(loop)
    return asyncio.Task.all_tasks(loop)


if hasattr(unittest, "IsolatedAsyncioTestCase"):
    AsyncTestCase = unittest.IsolatedAsyncioTestCase
else:
    class AsyncTestCase(unittest.TestCase):
        """Minimal IsolatedAsyncioTestCase backport for Python < 3.8.

        Runs each async test method, asyncSetUp, and asyncTearDown in a
        freshly created event loop that is closed and discarded afterwards.
        """

        def call_async(self, coro):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                try:
                    pending = get_pending_tasks(loop)
                    for t in pending:
                        t.cancel()
                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                finally:
                    loop.close()
                    asyncio.set_event_loop(None)

        def setUp(self):
            if hasattr(self, "asyncSetUp"):
                self.call_async(self.asyncSetUp())

        def tearDown(self):
            if hasattr(self, "asyncTearDown"):
                self.call_async(self.asyncTearDown())

        def run(self, result=None):
            method = getattr(self, self._testMethodName)
            if asyncio.iscoroutinefunction(method):
                original = method

                def sync_wrap():
                    return self.call_async(original())

                setattr(self, self._testMethodName, sync_wrap)
            return super(AsyncTestCase, self).run(result)


# ─────────────────────────────────────────────────────────────
# Loopback IP probing
# ─────────────────────────────────────────────────────────────

def probe_loopback_ips(max_count=16):
    """Return the loopback IPs in 127.0.0.0/8 that can be bound on this host.

    On Linux and Windows the full /8 is available; on macOS only 127.0.0.1
    responds by default.  Stops at the first bind failure so the probe is
    fast even on restricted systems.  Always returns at least ["127.0.0.1"].
    """
    available = []
    for i in range(1, 255):
        ip = "127.0.0.{}".format(i)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, 0))
            s.close()
            available.append(ip)
            if len(available) >= max_count:
                break
        except OSError:
            break
    return available or ["127.0.0.1"]


# ─────────────────────────────────────────────────────────────
# FakeInterface
# ─────────────────────────────────────────────────────────────

class FakeInterface(object):
    """Lightweight interface stub presenting exactly one IP for a single AF.

    Wraps the route metadata of a real Interface so that socket bind, pipe
    creation, and NIC-scope-id lookups work correctly, but forces all
    binding to happen on the specified IP address.

    Parameters
    ----------
    name       : str   — interface name (used for display / scope IDs on Linux)
    nic_id     : any   — numeric index or name used as the IPv6 scope ID
    af         : int   — IP4 or IP6
    ip         : str   — the IP address this interface presents
    base_route : Route — real Route to deep-copy metadata from; None for a
                         fully synthetic loopback-only interface
    """

    def __init__(self, name, nic_id, af, ip, base_route):
        self.name = name
        self.id = nic_id
        self.af = af
        self.ip = ip
        self.base_route = base_route
        self.resolved = True
        self.nat = None
        self.guid = None

    def route(self, req_af=None):
        if req_af is not None and req_af != self.af:
            raise LookupError("No route for {} found.".format(req_af))
        ipr = IPRange(self.ip)
        if self.base_route is not None:
            r = copy.deepcopy(self.base_route)
            r.nic_ips = [ipr]
            r.resolved = False
            r.interface = self
            r.bind = bind_closure(r, binder_async)
            return r
        # Fully synthetic path: no real route available (isolated machine).
        r = Route(
            af=self.af,
            nic_ips=[ipr],
            ext_ips=[ipr],
            interface=self,
            ext_check=0,
        )
        r.bind = bind_closure(r, binder_async)
        return r

    def nic(self, af=None):
        return self.ip

    def supported(self, skip_resolve=0):
        return [self.af]

    def is_default(self, af=None, gws=None):
        return False

    def get_scope_id(self):
        return self.id


# ─────────────────────────────────────────────────────────────
# FakeInterfaceFactory
# ─────────────────────────────────────────────────────────────

class FakeInterfaceFactory(object):
    """Builds a pool of FakeInterface objects from the machine's live routes.

    IP priority:
      IPv4 — real NIC IPs first, then probed 127.0.0.x loopback addresses
             so tests that need N distinct IPv4 binds always have options.
      IPv6 — real link-local and assigned addresses; ::1 always included as
             a final fallback so IPv6 tests can skip cleanly rather than crash.

    Usage:
        factory = await FakeInterfaceFactory.create()

        # Two IPv4 interfaces for a two-node test:
        ifaces = factory.get(2, IP4)
        if len(ifaces) < 2:
            self.skipTest("need 2 distinct IPv4 addresses")

        # All available IPv6 interfaces:
        v6 = factory.all(IP6)
    """

    def __init__(self):
        self.by_af = {IP4: [], IP6: []}
        self.anchor_route = {IP4: None, IP6: None}

    @classmethod
    async def create(cls, skip_nat=True):
        """Discover live interfaces and build the factory pool."""
        factory = cls()
        seen = {IP4: set(), IP6: set()}

        try:
            if_names = await list_interfaces()
            real_ifs = await load_interfaces(if_names, Interface, skip_nat=skip_nat)
        except Exception:
            real_ifs = []

        for nic in real_ifs:
            for af in nic.supported():
                try:
                    route = nic.route(af)
                except (LookupError, ValueError):
                    continue

                if factory.anchor_route[af] is None:
                    factory.anchor_route[af] = route

                nic_id = getattr(nic, "id", None) or nic.name
                all_ips = list(route.nic_ips) + list(
                    getattr(route, "link_locals", [])
                )
                for ipr in all_ips:
                    ip = ipr.ip
                    if ip not in seen[af]:
                        seen[af].add(ip)
                        factory.by_af[af].append(
                            FakeInterface(nic.name, nic_id, af, ip, route)
                        )

        # Fill IPv4 pool with probed loopback addresses so tests needing
        # multiple IPs work on single-NIC machines (Linux/Windows: full /8;
        # macOS: just 127.0.0.1).
        anchor_v4 = factory.anchor_route[IP4]
        for ip in probe_loopback_ips():
            if ip not in seen[IP4]:
                seen[IP4].add(ip)
                factory.by_af[IP4].append(
                    FakeInterface("loopback", 0, IP4, ip, anchor_v4)
                )

        # Always provide ::1 as a last-resort IPv6 address.
        if "::1" not in seen[IP6]:
            seen[IP6].add("::1")
            factory.by_af[IP6].append(
                FakeInterface("loopback6", 0, IP6, "::1", factory.anchor_route[IP6])
            )

        return factory

    def get(self, n=1, af=IP4):
        """Return up to n FakeInterface objects for the given AF."""
        return self.by_af[af][:n]

    def all(self, af):
        """Return all FakeInterface objects for the given AF."""
        return list(self.by_af[af])

    def count(self, af):
        """Return the number of available FakeInterface objects for the given AF."""
        return len(self.by_af[af])


def make_fake_nic(real_nic, af, target_ipr):
    """Convenience wrapper: build a FakeInterface pinned to target_ipr.

    Equivalent to FakeInterfaceFactory entries but created ad-hoc from a
    real Interface you already have in hand.  target_ipr is an IPRange.
    """
    return FakeInterface(
        real_nic.name,
        getattr(real_nic, "id", 0),
        af,
        target_ipr.ip,
        real_nic.route(af),
    )
