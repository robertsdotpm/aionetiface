import asyncio
from .net_defs import *

async def proto_recv(pipe):
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            return await pipe.recv()
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

async def proto_send(pipe, buf):
    n = 1 if pipe.sock.type == TCP else 5
    for i in range(0, n):
        try:
            await pipe.send(buf)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

        # Space out UDP retries; no delay after the final attempt.
        if n > 1 and i < n - 1:
            await asyncio.sleep(0.1)

async def send_recv_loop(dest, pipe, buf, sub=SUB_ALL):
    n = 1 if pipe.sock.type == TCP else 3
    for _ in range(0, n):
        try:
            await pipe.send(buf, dest)
            return await pipe.recv(
                sub=sub,
                timeout=pipe.conf["recv_timeout"]
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            log_exception()
            continue
        except Exception:
            # Broken socket, connection reset, etc. — retry.
            log_exception()
            continue

    return None
