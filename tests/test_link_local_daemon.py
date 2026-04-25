"""
Tests for link-local scope connect via Daemon.listen_local().

listen_local() binds IPv6 servers to link-local addresses (fe80::/10).
Connecting to a link-local requires the OS to embed a scope ID (interface
name on Linux/macOS, numeric index on Windows) in the socket address.

These are integration tests — they require the host to have at least one
IPv6-capable interface with a link-local address assigned.  All tests skip
gracefully when that condition is not met.

Ports used: 34600–34699 (avoid overlap with other test files).

Run with:
    python3 -m pytest tests/test_link_local_daemon.py -v
"""

from typing import Any
from aionetiface import *
from aionetiface.testing import AsyncTestCase
from port_helpers import xdist_port_base


BASE_PORT = xdist_port_base(34600)
MSG = b"link-local scope test"


def _get_link_local(interface: Any):
    """Return the first link-local string for the interface, or None."""
    try:
        route = interface.route(IP6)
    except (LookupError, ValueError):
        return None
    if not route.link_locals:
        return None
    return ipr_norm(route.link_locals[0])


class TestListenLocalLinkLocal(AsyncTestCase):
    """Daemon.listen_local() binds to link-local addresses and accepts connections."""

    async def asyncSetUp(self):
        self.interface = await Interface()
        self.link_local = _get_link_local(self.interface)
        if self.link_local is None:
            self.skipTest("No IPv6 link-local address on this host")

    # ── TCP ──────────────────────────────────────────────────────────────────

    async def test_tcp_echo_via_link_local(self):
        port = BASE_PORT
        echod = EchoServer()
        await echod.listen_local(TCP, port, self.interface)

        dest = (self.link_local, port)
        route = await self.interface.route(IP6).bind(ips=self.link_local)
        pipe = await Pipe(TCP, dest, route).connect()
        try:
            self.assertIsNotNone(pipe)
            pipe.subscribe(SUB_ALL)
            await pipe.send(MSG, dest)
            data = await pipe.recv(SUB_ALL)
            self.assertEqual(data, MSG)
        finally:
            await async_wrap_errors(pipe.close())
            await async_wrap_errors(echod.close())

    async def test_tcp_server_pipe_accessible_via_accept(self):
        port = BASE_PORT + 1
        echod = EchoServer()
        await echod.listen_local(TCP, port, self.interface)

        dest = (self.link_local, port)
        route = await self.interface.route(IP6).bind(ips=self.link_local)
        pipe = await Pipe(TCP, dest, route).connect()
        try:
            pipe.subscribe(SUB_ALL)
            await pipe.send(MSG, dest)
            await pipe.recv(SUB_ALL)

            # The server's accepted-client pipe is accessible via pipe_events.
            client_pipe = await pipe.pipe_events
            self.assertIsNotNone(client_pipe)
            client_pipe.subscribe(SUB_ALL)
            await pipe.send(MSG, dest)
            data = await client_pipe.recv(SUB_ALL)
            self.assertEqual(data, MSG)
        finally:
            await async_wrap_errors(pipe.close())
            await async_wrap_errors(echod.close())

    # ── UDP ──────────────────────────────────────────────────────────────────

    async def test_udp_echo_via_link_local(self):
        port = BASE_PORT + 2
        echod = EchoServer()
        await echod.listen_local(UDP, port, self.interface)

        dest = (self.link_local, port)
        route = await self.interface.route(IP6).bind(ips=self.link_local)
        pipe = await Pipe(UDP, dest, route).connect()
        try:
            self.assertIsNotNone(pipe)
            pipe.subscribe(SUB_ALL)
            await pipe.send(MSG, dest)
            data = await pipe.recv(SUB_ALL)
            self.assertEqual(data, MSG)
        finally:
            await async_wrap_errors(pipe.close())
            await async_wrap_errors(echod.close())

    # ── Server registration ───────────────────────────────────────────────────

    async def test_server_is_registered_under_link_local_ip(self):
        port = BASE_PORT + 3
        echod = EchoServer()
        await echod.listen_local(TCP, port, self.interface)
        try:
            ip6_tcp_servers = echod.servers[IP6][TCP]
            self.assertIn(port, ip6_tcp_servers, "no IPv6 TCP server at the expected port")
            registered_ips = list(ip6_tcp_servers[port].keys())
            self.assertTrue(
                any(ip.startswith("fe80") or ip.startswith("fd") for ip in registered_ips),
                "server should be bound to a link-local address, got: {}".format(registered_ips),
            )
        finally:
            await async_wrap_errors(echod.close())

    async def test_listen_local_returns_non_empty_list(self):
        port = BASE_PORT + 4
        echod = EchoServer()
        try:
            result = await echod.listen_local(TCP, port, self.interface)
            self.assertTrue(len(result) > 0, "listen_local returned no listeners")
        finally:
            await async_wrap_errors(echod.close())

    # ── Limit parameter ───────────────────────────────────────────────────────

    async def test_limit_zero_creates_no_ipv6_servers(self):
        port = BASE_PORT + 5
        echod = EchoServer()
        await echod.listen_local(TCP, port, self.interface, limit=0)
        try:
            ip6_tcp = echod.servers[IP6][TCP]
            self.assertNotIn(
                port, ip6_tcp,
                "limit=0 should prevent any IPv6 server from being registered",
            )
        finally:
            await async_wrap_errors(echod.close())

    async def test_limit_one_creates_at_most_one_ipv6_server(self):
        port = BASE_PORT + 6
        echod = EchoServer()
        await echod.listen_local(TCP, port, self.interface, limit=1)
        try:
            ip6_tcp = echod.servers[IP6][TCP]
            if port in ip6_tcp:
                self.assertLessEqual(
                    len(ip6_tcp[port]), 1,
                    "limit=1 should create at most one IPv6 server per port",
                )
        finally:
            await async_wrap_errors(echod.close())

    # ── Context manager ───────────────────────────────────────────────────────

    async def test_context_manager_closes_server(self):
        port = BASE_PORT + 7
        async with EchoServer() as echod:
            await echod.listen_local(TCP, port, self.interface)
            ip6_tcp = echod.servers[IP6][TCP]
            self.assertIn(port, ip6_tcp)
            server_pipe = next(iter(ip6_tcp[port].values()))

        # After the context exits, all server sockets should be closed.
        self.assertTrue(server_pipe.sock is None or server_pipe.sock._closed)

    # ── Two sends on the same pipe ────────────────────────────────────────────

    async def test_multiple_messages_on_same_tcp_connection(self):
        port = BASE_PORT + 8
        echod = EchoServer()
        await echod.listen_local(TCP, port, self.interface)

        dest = (self.link_local, port)
        route = await self.interface.route(IP6).bind(ips=self.link_local)
        pipe = await Pipe(TCP, dest, route).connect()
        try:
            pipe.subscribe(SUB_ALL)
            for i in range(3):
                msg = MSG + str(i).encode()
                await pipe.send(msg, dest)
                data = await pipe.recv(SUB_ALL)
                self.assertEqual(data, msg)
        finally:
            await async_wrap_errors(pipe.close())
            await async_wrap_errors(echod.close())


if __name__ == "__main__":
    main()
