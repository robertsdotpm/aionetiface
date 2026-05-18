"""
On old versions of Python < (3, 8) on Windows with the ProactorEventLoop,
asyncio's default UDP transport does not work. This module provides
a fallback implementation using low-level socket operations.
"""

import asyncio
import socket


class PolledDatagramTransport:
    """Polled datagram transport for platforms where asyncio UDP is unavailable."""

    def __init__(self, loop, sock, protocol):
        self.loop = loop
        self.sock = sock
        self.protocol = protocol
        self.closing = False
        self.consecutive_errors = 0

        # Windows: a UDP sendto whose destination replies with an ICMP
        # port-unreachable poisons the socket so the *next* recvfrom
        # raises WSAECONNRESET (WinError 10054). It is per-bounced-
        # datagram, not a broken socket -- but poll()'s recvfrom loop
        # would otherwise break on it and count it toward the
        # consecutive-error close, starving the real datagram queued
        # behind it. This bit udp_punch hard: the spray fires at many
        # predicted ports, most are closed, each closed port bounces an
        # ICMP unreachable. On IPv6 the ICMPv6 unreachables come back
        # reliably; on IPv4 they are usually rate-limited / filtered --
        # which is exactly why v4 punch survived and v6 punch did not.
        # SIO_UDP_CONNRESET=False turns the behaviour off at the source
        # so recvfrom only ever returns real datagrams.
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except OSError:
                pass

        self.sock.setblocking(False)
        protocol.connection_made(self)

    def poll(self):
        """Drain all pending datagrams from the socket and deliver them to the protocol."""
        if self.closing:
            return

        try:
            while True:
                data, addr = self.sock.recvfrom(65536)
                self.consecutive_errors = 0
                self.protocol.datagram_received(data, addr)
        except BlockingIOError:
            self.consecutive_errors = 0
        except OSError as e:
            self.consecutive_errors += 1
            self.protocol.error_received(e)
            # A socket that errors on every recv is genuinely broken.
            # Close it so poll_loop stops and the event loop can clean
            # up without waiting for a 60-second test timeout. The
            # Windows WSAECONNRESET-after-ICMP-unreachable case is no
            # longer the cause here -- SIO_UDP_CONNRESET in __init__
            # suppresses it at the source -- so reaching this count
            # now means a real failure.
            if self.consecutive_errors >= 10:
                self.close()

    def sendto(self, data, addr=None):
        """Send a datagram to addr (or the connected remote if addr is None)."""
        if self.closing:
            return

        try:
            if addr is None:
                self.sock.send(data)
            else:
                self.sock.sendto(data, addr)

        except OSError as e:
            self.protocol.error_received(e)

    def close(self):
        """Mark transport as closing, close the socket, and notify the protocol."""
        if self.closing:
            return
        self.closing = True
        fd = self.sock.fileno()
        self.sock.close()
        self.protocol.connection_lost(None)
        # PolledDatagramTransport sockets are never registered with the selector,
        # so ProxySelector.unregister never fires and CLOSE_FUTURES entries for
        # this fd would never resolve. Signal them manually here.
        if fd != -1:
            from .event_loop import CLOSE_FUTURES
            entries = CLOSE_FUTURES.pop(fd, [])
            for _, fut in entries:
                if not fut.done():
                    self.loop.call_soon(fut.set_result, True)

    def is_closing(self):
        """Return True if this transport has been closed or is in the process of closing."""
        return self.closing

    def get_extra_info(self, name, default=None):
        """Return transport-level metadata by name, or default if not available."""
        if name == "socket":
            return self.sock
        return default


class UdpPoller:
    """Periodically polls all registered PolledDatagramTransports and delivers received data."""

    def __init__(self, loop):
        self.loop = loop
        self.sockets = []
        self.interval = 0.01  # 10ms polling interval
        self.task = loop.create_task(self.poll_loop())

    def register(self, transport):
        """Add a PolledDatagramTransport to the set of sockets to be polled."""
        self.sockets.append(transport)
        if self.task is None or self.task.done():
            self.task = self.loop.create_task(self.poll_loop())

    def close(self):
        """Schedule cancellation of the polling task (non-blocking)."""
        if self.task and not self.task.done():
            self.task.cancel()

    async def aclose(self):
        """Async close — cancels the polling task and waits for it to exit."""
        self.close()
        if self.task is not None:
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None

    async def poll_loop(self):
        """Poll registered transports until all are closed or task is cancelled."""
        while self.sockets:
            self.sockets = [t for t in self.sockets if not t.is_closing()]
            for transport in self.sockets:
                transport.poll()
            await asyncio.sleep(self.interval)
