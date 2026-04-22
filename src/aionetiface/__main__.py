"""Command-line entry point for the aionetiface test console."""
import ast
import asyncio
import code
import concurrent.futures
import inspect
import sys
import threading
import types
import warnings
import multiprocessing
import platform
from typing import Any
from asyncio import futures

vmaj, vmin, _ = platform.python_version_tuple()
SUPPORTS_TOP_LEVEL_AWAIT = int(vmaj) >= 3 and int(vmin) >= 8
SUPPORTS_INTERACT_EXITMSG = int(vmaj) >= 3 and int(vmin) >= 6

from .do_imports import *  # noqa: E402


class AsyncIOInteractiveConsole(code.InteractiveConsole):
    """Interactive console; supports top-level await on Python 3.8+."""

    def __init__(self, locals, loop):
        super().__init__(locals)
        if SUPPORTS_TOP_LEVEL_AWAIT:
            self.compile.compiler.flags |= ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
        self.loop = loop

    def runcode(self, code: Any) -> None:
        """Compile and run a code object, scheduling any coroutine result on the event loop."""
        future = concurrent.futures.Future()

        def callback():
            """Schedule the compiled code object as a task on the asyncio loop."""
            global repl_future
            global repl_future_interrupted

            repl_future = None
            repl_future_interrupted = False

            func = types.FunctionType(code, self.locals)
            try:
                coro = func()
            except SystemExit:
                raise
            except KeyboardInterrupt as ex:
                repl_future_interrupted = True
                future.set_exception(ex)
                return
            except BaseException as ex:
                future.set_exception(ex)
                return

            if not inspect.iscoroutine(coro):
                future.set_result(coro)
                return

            try:
                repl_future = self.loop.create_task(coro)
                futures._chain_future(repl_future, future)
            except BaseException as exc:
                future.set_exception(exc)

        loop.call_soon_threadsafe(callback)

        try:
            return future.result()
        except SystemExit:
            raise
        except BaseException:
            if repl_future_interrupted:
                self.write("\nKeyboardInterrupt\n")
            else:
                self.showtraceback()


class REPLThread(threading.Thread):
    """Background thread that drives the interactive REPL console."""

    def run(self) -> None:
        """Start the interactive console banner and enter the REPL loop."""
        try:
            loop_policy = str(asyncio.get_event_loop_policy())
            if "elector" in loop_policy:
                loop_policy = "selector"

            spawn_method = multiprocessing.get_start_method()
            vmaj, vmin, _ = platform.python_version_tuple()
            banner = (
                fstr(
                    "aionetiface REPL on Python {1}.{2} / {3}",
                    (
                        0,
                        vmaj,
                        vmin,
                        sys.platform,
                    ),
                ),
                fstr(
                    "Loop = {0}, Process = {1}",
                    (
                        loop_policy,
                        spawn_method,
                    ),
                ),
                'Use "await" directly instead of "asyncio.run()".',
                fstr("{0}from aionetiface import *", (getattr(sys, "ps1", ">>> "),)),
            )

            console.push("from aionetiface.do_imports import *")
            interact_kwargs = {"banner": "\n".join(banner)}
            if SUPPORTS_INTERACT_EXITMSG:
                interact_kwargs["exitmsg"] = "exiting asyncio REPL..."
            console.interact(**interact_kwargs)

        finally:
            warnings.filterwarnings(
                "ignore",
                message=r"^coroutine .* was never awaited$",
                category=RuntimeWarning,
            )

            loop.call_soon_threadsafe(loop.stop)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    repl_locals = {"asyncio": asyncio}
    for key in {
        "__name__",
        "__package__",
        "__loader__",
        "__spec__",
        "__builtins__",
        "__file__",
    }:
        repl_locals[key] = locals()[key]

    console = AsyncIOInteractiveConsole(repl_locals, loop)

    repl_future = None
    repl_future_interrupted = False

    try:
        import readline  # NoQA
    except ImportError:
        pass

    repl_thread = REPLThread()
    repl_thread.daemon = True
    repl_thread.start()

    while True:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            if repl_future and not repl_future.done():
                repl_future.cancel()
                repl_future_interrupted = True
            continue
        else:
            break

    # ---- Clean shutdown ----
    # Cancel every pending task so sockets / transports are closed properly
    # and Python doesn't emit "Task was destroyed but it is pending!" or
    # "unclosed socket" ResourceWarnings.
    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.6
        pending = asyncio.Task.all_tasks(loop)

    for task in pending:
        task.cancel()

    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    try:
        if hasattr(loop, "shutdown_asyncgens"):
            loop.run_until_complete(loop.shutdown_asyncgens())
        if hasattr(loop, "shutdown_default_executor"):
            loop.run_until_complete(loop.shutdown_default_executor())
    finally:
        loop.close()
