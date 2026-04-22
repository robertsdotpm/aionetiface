"""Higher-level send/receive patterns built on raw sockets."""
import asyncio
from typing import Any
from ..utility.utils import log_exception
from .net_defs import SUB_ALL, TCP


async def proto_recv(pipe: Any) -> Any:
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            return await pipe.recv()
        except (OSError, ConnectionError, asyncio.TimeoutError):
            continue


async def proto_send(pipe: Any, buf: bytes) -> None:
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


async def send_recv_loop(dest: Any, pipe: Any, buf: bytes, sub: Any = SUB_ALL) -> Any:
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
