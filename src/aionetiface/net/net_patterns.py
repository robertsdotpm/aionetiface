"""Higher-level send/receive patterns built on raw sockets."""
import asyncio
from ..utility.utils import log_exception
from .net_defs import SUB_ALL, TCP


async def proto_recv(pipe):
    """Receive a message from pipe, retrying up to 5 times for UDP connections."""
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            return await pipe.recv()
        except (OSError, ConnectionError, asyncio.TimeoutError):
            continue


async def proto_send(pipe, buf):
    """Send buf over pipe, retrying up to 5 times with brief delays for UDP connections."""
    n = 1 if pipe.sock.type == TCP else 5
    for i in range(0, n):
        try:
            await pipe.send(buf)
        except asyncio.CancelledError:
            raise
        except (OSError, ConnectionError):
            pass

        # Space out UDP retries; no delay after the final attempt.
        if n > 1 and i < n - 1:
            await asyncio.sleep(0.1)


async def send_recv_loop(dest, pipe, buf, sub=SUB_ALL):
    """Send buf to dest and wait for a matching reply, retrying up to 3 times for UDP."""
    n = 1 if pipe.sock.type == TCP else 3
    for _ in range(0, n):
        try:
            await pipe.send(buf, dest)
            return await pipe.recv(sub=sub, timeout=pipe.conf["recv_timeout"])
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            log_exception()
            continue
        except (OSError, ConnectionError):
            # Broken socket, connection reset, etc. — retry.
            log_exception()
            continue

    return None
