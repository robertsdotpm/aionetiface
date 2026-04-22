"""Simple echo server used for connectivity testing."""
import asyncio
from typing import Any, Tuple
from ...net.daemon import Daemon
from ...utility.utils import async_wrap_errors, get_running_loop
from ...utility.fstr import fstr
from ...net.asyncio.async_run import async_run


class EchoServer(Daemon):
    """Daemon that echoes every received message back to its sender."""
    def __init__(self) -> None:
        super().__init__()

    async def msg_cb(self, msg: bytes, client_tup: Tuple[Any, ...], pipe: Any) -> None:
        await async_wrap_errors(pipe.send(msg, client_tup))


if __name__ == "__main__":  # pragma: no cover
    print("See tests/test_daemon.py for code that uses this.")

    class EchoProtocol(asyncio.Protocol):
        """asyncio.Protocol that logs connections and echoes received data back to the peer."""
        def connection_made(self, transport):
            """Store the transport and log the new incoming connection address."""
            self.transport = transport
            print(transport)
            print(transport.get_extra_info("socket"))
            addr = transport.get_extra_info("peername")
            print(fstr("Connection from {0}", (addr,)))

        def data_received(self, data):
            """Echo the received data back to the sender and log the message."""
            message = data.decode()
            addr = self.transport.get_extra_info("peername")
            print(
                fstr(
                    "Received {0} from {1}",
                    (
                        message,
                        addr,
                    ),
                )
            )
            # Echo back
            self.transport.write(data)

        def connection_lost(self, exc):
            """Log the address of a peer whose connection has been closed."""
            addr = self.transport.get_extra_info("peername")
            print(fstr("Connection closed from {0}", (addr,)))

    async def echo_main():
        from aionetiface.src.aionetiface.net.net_utils import IP4, TCP
        from aionetiface.nic.interface import Interface

        loop = get_running_loop()
        server = await loop.create_server(lambda: EchoProtocol(), "127.0.0.1", 3000)

        print("Echo server listening on 127.0.0.1:3000")
        async with server:
            await server.serve_forever()

        nic = await Interface()
        echo_route = await nic.route(IP4).bind(ips="localhost", port=3000)
        # print(echo_route)
        # print(echo_route._bind_tups)

        # Daemon instance.
        echod = EchoServer()
        await echod.add_listener(TCP, echo_route)

        while True:
            await asyncio.sleep(1)

    async_run(echo_main())
