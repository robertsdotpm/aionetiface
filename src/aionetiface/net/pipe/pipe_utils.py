"""Utility functions shared across pipe implementations."""
import asyncio
from ..net_utils import client_tup_norm, ip_norm


def tup_to_sub(dest_tup):
    """Convert a (ip, port) destination tuple into a subscription tuple that matches any message from that peer."""
    dest_tup = client_tup_norm(dest_tup)
    return (
        b"",  # Any message.
        dest_tup,
    )


def norm_client_tup(client_tup):
    """Return a normalised (ip_string, port) tuple with the IP expanded to its canonical form."""
    ip = ip_norm(client_tup[0])
    return (ip, client_tup[1])


async def close_all_clients(
    tcp_clients, loop=None, timeout=1.0
):
    """Close all TCP client transports and await their OS-level socket release with an optional timeout."""
    if loop is None:
        loop = asyncio.get_event_loop()

    tasks = []
    for client in tcp_clients:
        if client.transport is not None:
            client.transport.close()
            client.transport = None

        sock = client.sock
        if sock is None:
            continue

        # Await the OS-level socket closure with timeout
        if hasattr(loop, "await_fd_close"):
            tasks.append(asyncio.wait_for(loop.await_fd_close(sock), timeout=timeout))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Optional: log exceptions
        for r in results:
            if isinstance(r, Exception):
                pass  # log or ignore
