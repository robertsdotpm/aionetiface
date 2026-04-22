"""Top-level async runner (event loop bootstrapping)."""
import asyncio
from asyncio import events, coroutines
from typing import Any, Optional, Type
from ...utility.cleanup import cancel_all_tasks


def patch_asyncio_backports(loop_cls: Optional[Type[Any]] = None) -> None:

    # Default to whatever class is passed, or fall back to the base event loop
    if loop_cls is None:
        try:
            if hasattr(asyncio, "get_running_loop"):
                loop_cls = type(asyncio.get_running_loop())
            else:
                raise RuntimeError("no running loop")
        except RuntimeError:
            _tmp = asyncio.new_event_loop()
            loop_cls = type(_tmp)
            _tmp.close()

    if not hasattr(loop_cls, "shutdown_asyncgens"):

        async def _noop(self):
            pass

        loop_cls.shutdown_asyncgens = _noop

    if not hasattr(loop_cls, "shutdown_default_executor"):

        async def _shutdown_default_executor(self):
            executor = getattr(self, "_default_executor", None)
            if executor is not None:
                executor.shutdown(wait=True)

        loop_cls.shutdown_default_executor = _shutdown_default_executor


def async_run(main: Any, *, debug: bool = False) -> Any:
    """Execute the coroutine and return the result.

    This function runs the passed coroutine, taking care of
    managing the asyncio event loop and finalizing asynchronous
    generators.

    This function cannot be called when another asyncio event loop is
    running in the same thread.

    If debug is True, the event loop will be run in debug mode.

    This function always creates a new event loop and closes it at the end.
    It should be used as a main entry point for asyncio programs, and should
    ideally only be called once.
    """
    if events._get_running_loop() is not None:
        raise RuntimeError("asyncio.run() cannot be called from a running event loop")

    if not coroutines.iscoroutine(main):
        raise ValueError("a coroutine was expected, got {!r}".format(main))

    loop = events.new_event_loop()
    try:
        events.set_event_loop(loop)
        loop.set_debug(debug)
        return loop.run_until_complete(main)
    finally:
        try:
            cancel_all_tasks(loop)
            if hasattr(loop, "shutdown_asyncgens"):
                loop.run_until_complete(loop.shutdown_asyncgens())

            if hasattr(loop, "shutdown_default_executor"):
                loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            events.set_event_loop(None)
            loop.close()
