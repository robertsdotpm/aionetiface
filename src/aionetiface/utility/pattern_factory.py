"""Factory helpers for building concurrent async patterns."""
import asyncio
from collections import defaultdict
from typing import Any, List, Optional
from .utils import fstr, log


async def concurrent_first_agree_or_best(
    min_agree: int, tasks: List[Any], timeout: float, wait_all: bool = False
) -> Optional[Any]:
    results = defaultdict(int)
    log(
        fstr(
            "Con first agree: min={0}. task_no={1}, timeout={2}, wait_all={3}",
            (min_agree, len(tasks), timeout, wait_all),
        )
    )

    def check_consensus(result):
        if result is None or isinstance(result, Exception):
            return None
        results[result] += 1
        if results[result] >= min_agree:
            return result
        return None

    # Convert coroutines to Tasks so they can be individually cancelled.
    scheduled = [
        t if isinstance(t, asyncio.Task) else asyncio.ensure_future(t) for t in tasks
    ]

    winner = None
    try:
        if wait_all:
            done, pending = await asyncio.wait(scheduled, timeout=timeout)
            for t in pending:
                t.cancel()
            for t in done:
                try:
                    winner = check_consensus(t.result())
                except (Exception, asyncio.CancelledError):
                    pass
                if winner is not None:
                    break
        else:
            try:
                for fut in asyncio.as_completed(scheduled, timeout=timeout):
                    try:
                        result = await fut
                        winner = check_consensus(result)
                    except (Exception, asyncio.CancelledError):
                        pass
                    if winner is not None:
                        break
            except asyncio.TimeoutError:
                pass
    finally:
        for t in scheduled:
            if not t.done():
                t.cancel()

    return winner


async def repeat_every(n: float, coro_func: Any, *args: Any, **kwargs: Any) -> None:
    while True:
        await coro_func(*args, **kwargs)
        await asyncio.sleep(n)
