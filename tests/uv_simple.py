import asyncio
import uvloop

class EchoProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Echo the received data back to the sender
        self.transport.sendto(data, addr)

async def main():
    loop = asyncio.get_running_loop()

    # Start the UDP echo server
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoProtocol(),
        local_addr=("127.0.0.1", 9999),
    )
    print("UDP echo server listening on 127.0.0.1:9999")

    # Small delay to ensure the server is ready
    await asyncio.sleep(0.1)

    # UDP client: send a message and receive the echo
    message = b"hello uvloop"
    on_response = asyncio.Future()

    class ClientProtocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            transport.sendto(message, ("127.0.0.1", 9999))
            self.transport = transport

        def datagram_received(self, data, addr):
            on_response.set_result(data)
            self.transport.close()

    await loop.create_datagram_endpoint(
        lambda: ClientProtocol(),
        remote_addr=("127.0.0.1", 9999),
    )

    # Wait for the echoed message
    data = await on_response
    print("Client received:", data)

    # Clean up server
    transport.close()

if __name__ == "__main__":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    asyncio.run(main())
