"""
On old versions of Python < (3, 8) on Windows with the ProactorEventLoop,
asyncio's default UDP transport does not work. This module provides
a fallback implementation using low-level socket operations.
"""

import asyncio
import socket

class PolledDatagramTransport:
    def __init__(self, loop, sock, protocol):
        self.loop = loop
        self.sock = sock
        self.protocol = protocol
        self.closing = False

        self.sock.setblocking(False)
        protocol.connection_made(self)

    def poll(self):
        if self.closing:
            return

        try:
            while True:
                data, addr = self.sock.recvfrom(65536)
                self.protocol.datagram_received(data, addr)
        except BlockingIOError:
            pass
        except OSError as e:
            self.protocol.error_received(e)

    def sendto(self, data, addr=None):
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
        if self.closing:
            return
        self.closing = True
        self.sock.close()
        self.protocol.connection_lost(None)

    def is_closing(self):
        return self.closing

    def get_extra_info(self, name, default=None):
        if name == "socket":
            return self.sock
        return default

class UdpPoller:
    def __init__(self, loop):
        self.loop = loop
        self.sockets = []
        self.interval = 0.01  # 10ms polling interval
        self.task = loop.create_task(self.poll_loop())

    def register(self, transport):
        self.sockets.append(transport)

    async def poll_loop(self):
        while True:
            for transport in self.sockets:
                if not transport.is_closing():
                    transport.poll()
                    
            await asyncio.sleep(self.interval)