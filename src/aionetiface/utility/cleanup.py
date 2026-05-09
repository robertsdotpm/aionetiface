"""asyncio task cancellation and cleanup helpers."""
import os
import sys
import asyncio
import multiprocessing
import signal as signal_mod
from .error_logger import log, log_exception
from .async_helpers import get_running_loop


__all__ = [
    "cancel_task",
    "cancel_tasks",
    "rm_done_tasks",
    "gather_or_cancel",
    "handle_exceptions",
    "cancel_all_tasks",
    "shutdown_executor_with_timeout",
    "shutdown_proc_pool",
]


async def cancel_task(task):
    """Cancel a single asyncio task and await its completion, ignoring errors."""
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def cancel_tasks(tasks):
    """Cancel all live tasks in the list and await them together."""
    live = [t for t in tasks if not t.done()]
    for t in live:
        t.cancel()
    if live:
        await asyncio.gather(*live, return_exceptions=True)


def rm_done_tasks(tasks):
    """Return a new list containing only tasks that have not yet completed."""
    return [task for task in tasks if not task.done()]


async def gather_or_cancel(tasks, timeout):
    """Wait for all tasks within timeout; cancel all if the timeout expires."""
    group = asyncio.gather(*tasks, return_exceptions=True)
    try:
        await asyncio.wait_for(group, timeout)
    except asyncio.TimeoutError:
        for task in tasks:
            task.cancel()
        cancelled = asyncio.gather(*tasks, return_exceptions=True)
        await cancelled
        await asyncio.sleep(0)
    except asyncio.CancelledError:
        return []
    except (RuntimeError, asyncio.InvalidStateError):
        log_exception()
        return []


def handle_exceptions(loop, context):
    """No-op asyncio exception handler — silences stray teardown errors."""


def cancel_all_tasks(loop):
    """Cancel every pending task on loop and wait for cancellations to drain."""
    try:
        to_cancel = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.4–3.6 fallback.
        Task = getattr(asyncio, "Task", None)
        if Task is None or not hasattr(Task, "all_tasks"):
            import types

            for _, mod in list(asyncio.__dict__.items()):
                if isinstance(mod, types.ModuleType) and hasattr(mod, "Task"):
                    Task = mod.Task
                    break
        to_cancel = Task.all_tasks(loop) if Task else set()

    if not to_cancel:
        return

    for task in to_cancel:
        task.cancel()

    loop.run_until_complete(asyncio.gather(*to_cancel, return_exceptions=True))
    for task in to_cancel:
        if task.cancelled():
            continue
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            continue
        if exc is not None:
            loop.call_exception_handler(
                {
                    "message": "unhandled exception during asyncio.run() shutdown",
                    "exception": exc,
                    "task": task,
                }
            )


async def shutdown_executor_with_timeout(executor, timeout=3):
    """Shut down a concurrent.futures.Executor with a timeout."""
    loop = get_running_loop()
    shutdown_future = loop.run_in_executor(None, executor.shutdown, True)
    try:
        await asyncio.wait_for(shutdown_future, timeout=timeout)
    except asyncio.TimeoutError:
        log("Warning: executor shutdown timed out")


async def shutdown_proc_pool(proc_pool):
    """Shut down a punch worker pool (ThreadPoolExecutor or ProcessPoolExecutor).

    p2pd's tcp_punch plugin uses ThreadPoolExecutor now (Windows Python
    3.8 ProcessPoolExecutor was unstable), so this function gets passed
    a thread pool in the typical case. The multiprocessing-specific
    teardown (_processes, active_children, terminate) is skipped when
    the pool isn't a process pool. Threads exit when their target
    function returns, and ThreadPoolExecutor.shutdown handles the rest.
    """
    log("trying to shut down pp executor waiting.")

    # Fast path for ThreadPoolExecutor: no _processes attribute, just
    # shutdown(). cancel_futures available on 3.9+.
    is_process_pool = hasattr(proc_pool, "_processes")
    if not is_process_pool:
        if sys.version_info >= (3, 9):
            proc_pool.shutdown(wait=False, cancel_futures=True)
        else:
            proc_pool.shutdown(wait=False)
        return

    executor_pids = set()
    try:
        executor_pids = set(proc_pool._processes.keys())
    except AttributeError:
        pass

    if sys.version_info >= (3, 9):
        proc_pool.shutdown(wait=False, cancel_futures=True)
    else:
        proc_pool.shutdown(wait=False)

    # Wait up to 3 seconds for worker processes to exit gracefully.
    loop = get_running_loop()
    end = loop.time() + 3
    while True:
        active = multiprocessing.active_children()
        remaining = (
            {c for c in active if c.pid in executor_pids}
            if executor_pids
            else set(active)
        )
        if not remaining or loop.time() >= end:
            break
        await asyncio.sleep(0.5)

    # SIGTERM any survivors.
    active = multiprocessing.active_children()
    targets = [c for c in active if not executor_pids or c.pid in executor_pids]
    for child in targets:
        child.terminate()

    # On non-Windows, escalate to SIGKILL if they're still alive after 0.2s.
    if sys.platform != "win32" and targets:
        await asyncio.sleep(0.2)
        active_pids = {c.pid for c in multiprocessing.active_children()}
        for child in targets:
            if child.pid in active_pids:
                try:
                    os.kill(child.pid, signal_mod.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

    for child in targets:
        child.join(timeout=0.5)

    log("shutdown for pp executor done.")
