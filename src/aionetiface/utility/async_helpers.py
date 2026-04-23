"""asyncio helpers: task scheduling, gather/retry, executor wrappers."""
import asyncio
import functools
import inspect
import random
import sys
from typing import Any, Callable, List, Optional

from .fstr import fstr
from .error_logger import log, log_exception


__all__ = [
    "create_task",
    "get_running_loop",
    "safe_run",
    "return_true",
    "threshold_gather",
    "async_wrap_errors",
    "sync_wrap_errors",
    "async_retry",
    "async_test",
    "async_to_sync",
    "handler_done_builder",
    "run_handler",
    "run_handlers",
    "run_in_executor",
    "run_in_executor2",
    "safe_gather",
    "sleep_random",
]


# Status codes duplicated here to avoid a circular import with utils.
STATUS_RETRY = 1


def create_task(coro: Any, loop: Optional[Any] = None) -> Any:
    """Schedule coro as a task on the given (or current) event loop."""
    loop = loop or asyncio.get_event_loop()
    return loop.create_task(coro)


def get_running_loop() -> Optional[Any]:
    """Return the running event loop if one exists, falling back to get_event_loop() on Python < 3.7."""
    try:
        return asyncio.get_running_loop()
    except AttributeError:
        try:
            return asyncio.get_event_loop()
        except RuntimeError:
            return None
    except RuntimeError:
        return None


async def safe_run(f: Any, args: Optional[List[Any]] = None) -> None:
    """
    Run f(*args), then wait for all remaining tasks in the event loop to finish.

    Used as a wrapper in test harnesses.
    """
    if args is None:
        args = []
    await f(*args)

    tasks = asyncio.all_tasks()
    cur_task = asyncio.current_task()
    await asyncio.gather(*tasks - {cur_task})


async def return_true(result: Any = None) -> bool:
    """No-op coroutine that always returns True. Useful as a stub callback."""
    return True


async def threshold_gather(
    tasks: List[Any], result_filter: Callable[[List[Any]], List[Any]], threshold: int
) -> Optional[Any]:
    """
    Run tasks concurrently and return the first result that appears at least
    `threshold` times after applying result_filter.

    Returns None if no result reaches the threshold.
    """
    # Local import to avoid circular dependency with utils.
    from .utils import strip_none

    results = await asyncio.gather(*tasks)
    results = strip_none(results)
    results = sorted(result_filter(results))
    if not results:
        return None

    count = 0
    current = results[0]
    for value in results:
        if value == current:
            count += 1
        else:
            count = 1
            current = value

        if count >= threshold:
            return current

    return None


async def async_wrap_errors(
    coro: Any, timeout: Optional[int] = None, logging: bool = True
) -> Optional[Any]:
    """
    Await coro, optionally bounded by timeout seconds.

    Silently logs exceptions (except CancelledError which is re-raised).
    Returns the coroutine's result, or None if an exception occurred.
    """
    try:
        if timeout is None:
            return await coro
        if isinstance(timeout, int):
            return await asyncio.wait_for(coro, timeout)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except Exception:  # noqa: BLE001
        if logging:
            log("async_wrap_errors: exception caught")
            log_exception()


def sync_wrap_errors(
    f: Callable[..., Any], args: Optional[List[Any]] = None
) -> Optional[Any]:
    """
    Call f(*args) synchronously, logging any exception without re-raising.

    Returns the function's result, or None if an exception occurred.
    """
    try:
        if args:
            return f(*args)
        return f()
    except Exception:  # noqa: BLE001
        try:
            log_exception()
        except Exception:  # noqa: BLE001
            pass

    return None


async def async_retry(gen: Callable[[], Any], count: int, timeout: int = 4) -> None:
    """
    Retry the coroutine produced by gen() up to count times with the given timeout.

    gen() must return a tuple of (status_future, retry_coro, new_future_factory).
    Raises asyncio.TimeoutError if the retry limit is exceeded without success.
    """
    iteration = retries = 0
    while True:
        try:
            init_coro = gen()
            status_future, retry_coro, new_future = await asyncio.wait_for(
                init_coro, timeout
            )

            if iteration == 0:
                await retry_coro()

            status = await asyncio.wait_for(status_future, timeout)
            status_future = new_future()

            if status == STATUS_RETRY:
                iteration -= 1
                retries += 1
                await retry_coro()

            if status != STATUS_RETRY:
                return None

        except asyncio.TimeoutError:
            pass

        finally:
            iteration += 1
            if count in (iteration, retries):
                break

    raise asyncio.TimeoutError("async_retry: retry limit reached")


# Will be used in sample code to avoid boilerplate.
def async_test(coro: Any, loop: Optional[Any] = None) -> None:
    """
    Run a coroutine (or coroutine function) synchronously.

    Accepts either an already-created coroutine or a zero-argument coroutine
    function; calls it if it's a function.
    """
    if inspect.iscoroutinefunction(coro):
        coro = coro()

    if hasattr(asyncio, "run"):
        asyncio.run(coro)
    else:
        loop = loop or asyncio.get_event_loop()
        loop.run_until_complete(coro)


def async_to_sync(
    f: Callable[..., Any], params: Optional[Any] = None, loop: Optional[Any] = None
) -> Callable[..., Any]:
    """
    Wrap async function f into a synchronous callable.

    If params is provided, the returned closure accepts an args sequence.
    Otherwise the returned closure takes no arguments.

    Note: if there is already a running event loop (e.g. inside Jupyter),
    run nest_asyncio.apply() first to allow nested loops.
    """
    loop = loop or get_running_loop()

    if loop is None:
        raise AssertionError(
            "async_to_sync: no event loop available. "
            "Pass loop= explicitly or call from inside a running loop."
        )

    if params is not None:

        def closure(args):
            """Run f with the provided args sequence synchronously on loop and return the result."""
            return loop.run_until_complete(f(*args))

        return closure

    def closure():
        """Run f with no arguments synchronously on loop and return the result."""
        return loop.run_until_complete(f())

        return closure


# ---------------------------------------------------------------------------
# Handler / pipe event dispatch
# ---------------------------------------------------------------------------


def handler_done_builder(
    pipe: Any, handler: Any, task: Optional[Any] = None
) -> Callable[[Any], None]:
    """
    Return a done-callback for a handler task attached to pipe.

    Removes the task from pipe.handler_tasks, logs integer error codes,
    and saves any new Task returned by the handler onto pipe.tasks.
    """

    def on_done(result):
        """Remove the completed task from pipe, log any error code, and track any returned Task."""
        if task in pipe.tasks:
            pipe.handler_tasks.remove(task)

        if isinstance(result, int) and result:
            log(
                fstr(
                    "> {0} = error {1}.",
                    (
                        handler,
                        result,
                    ),
                )
            )

        if isinstance(result, asyncio.Task):
            pipe.tasks.append(result)

    return on_done


def run_handler(
    pipe: Any,
    handler: Callable[..., Any],
    client_tup: Any,
    data: Optional[bytes] = None,
) -> None:
    """
    Dispatch a single handler on a received message.

    Async handlers are scheduled as tasks and tracked in pipe.handler_tasks.
    Sync handlers are called immediately.
    """
    if inspect.iscoroutinefunction(handler):
        task = create_task(async_wrap_errors(handler(data, client_tup, pipe)))
        task.add_done_callback(handler_done_builder(pipe, handler, task))
        pipe.handler_tasks.append(task)
    else:
        result = handler(data, client_tup, pipe)
        handler_done_builder(pipe, handler)(result)


def run_handlers(
    pipe: Any,
    handlers: List[Callable[..., Any]],
    client_tup: Any,
    data: Optional[bytes] = None,
) -> None:
    """
    Dispatch all registered handlers for a pipe event.

    Cleans up completed handler tasks before dispatching new ones.
    """
    # Local import to avoid circular dependency with utils.
    from .cleanup import rm_done_tasks

    pipe.handler_tasks = rm_done_tasks(pipe.handler_tasks)
    for handler in handlers:
        run_handler(pipe, handler, client_tup, data)


# ---------------------------------------------------------------------------
# Executor wrappers
# ---------------------------------------------------------------------------


def run_in_executor(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator that runs f in a thread-pool executor.

    Sync functions are passed directly to the executor.
    Async functions are run in a fresh event loop inside the executor.
    """

    @functools.wraps(f)
    def inner(*args, **kwargs):
        """Submit f to the thread-pool executor, running it in a new event loop if async."""
        loop = get_running_loop()

        if not inspect.iscoroutinefunction(f):
            return loop.run_in_executor(None, lambda: f(*args, **kwargs))

        def helper():
            """Run the async function f in a fresh event loop and return its result."""
            new_loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(new_loop)
                return new_loop.run_until_complete(f(*args, **kwargs))
            finally:
                new_loop.close()

        return loop.run_in_executor(None, helper)

    return inner


def run_in_executor2(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator that schedules async functions as tasks, or runs sync
    functions in the executor.
    """

    @functools.wraps(f)
    def inner(*args, **kwargs):
        """Schedule f as a task if async, or run it in the executor if sync."""
        loop = asyncio.get_event_loop()
        if inspect.iscoroutinefunction(f):
            return loop.create_task(f(*args, **kwargs))
        return loop.run_in_executor(None, lambda: f(*args, **kwargs))

    return inner


# ---------------------------------------------------------------------------
# Concurrency safety
# ---------------------------------------------------------------------------


async def safe_gather(*args: Any) -> List[Any]:
    """
    Gather coroutines, but run them sequentially on Python 3.5 to avoid
    filling the executor pool, which is buggy on older interpreter versions.
    """
    if sys.version_info[1] <= 5:
        results = []
        for task in args:
            result = await task
            results.append(result)
        return results
    return await asyncio.gather(*args)


async def sleep_random(min_ms: int = 100, max_ms: int = 2000) -> None:
    """Sleep for a random duration between min_ms and max_ms milliseconds."""
    delay = random.randrange(min_ms, max_ms + 1) / 1000.0
    await asyncio.sleep(delay)
