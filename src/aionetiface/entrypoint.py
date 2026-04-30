"""Library initialisation: verifies Python version and probes default routes."""
import asyncio
import multiprocessing
import socket
import sys
from typing import Any
from .utility.utils import get_running_loop, log, log_exception
from .net.net_defs import AF_ANY, IP4
from .net.asyncio.event_loop import CustomEventLoop, CustomEventLoopPolicy
from .net.asyncio.async_run import patch_asyncio_backports, async_run
from .net.asyncio.asyncio_patches import SelectSelector, patched_select_modern, patched_select_old
from .nic.interface_utils import get_default_iface, get_interface_af

if sys.platform == "win32":
    from .nic.netifaces.windows.win_netifaces import Netifaces


__all__ = [
    "aionetiface_setup_netifaces",
    "aionetiface_setup_event_loop",
    "entrypoint_test",
]


_cached_netifaces = None
_cache_lock = None  # Lazily created inside the running event loop.

# aionetiface_setup_netifaces uses an asyncio.Lock to guard the init path.
# On Windows, netifaces is replaced by a pure-Python implementation that
# uses scripting approaches with regex and OS-specific fallbacks rather than
# binary extensions, so installation works without a C compiler.
# On Linux/BSD the standard netifaces package from PyPI is used directly.


async def aionetiface_setup_netifaces() -> Any:
    """Set up the event loop and return a platform-appropriate netifaces instance, caching the result."""
    global _cached_netifaces
    global _cache_lock
    if _cached_netifaces is not None:
        return _cached_netifaces

    # Create the lock lazily so it is always bound to the running event loop.
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()

    async with _cache_lock:
        # Double check inside lock
        if _cached_netifaces is not None:
            return _cached_netifaces

        # Setup event loop.
        loop = get_running_loop()
        loop.set_debug(False)
        loop.set_exception_handler(CustomEventLoopPolicy.exception_handler)

        # Attempt to get monkey patched netifaces.
        if sys.platform == "win32":
            netifaces = await Netifaces().start()
        else:
            import netifaces

        # Are UDP sockets blocked?
        # Firewalls like iptables on freehosts can do this.
        sock = None
        try:
            # Figure out what address family default interface supports.
            if_name = get_default_iface(netifaces)
            af = get_interface_af(netifaces, if_name)
            if af == AF_ANY:  # Duel stack. Just use v4.
                af = IP4

            # Set destination based on address family.
            if af == IP4:
                dest = ("8.8.8.8", 60000)
            else:
                dest = ("2001:4860:4860::8888", 60000)

            # Build new UDP socket.
            sock = socket.socket(family=af, type=socket.SOCK_DGRAM)

            # Attempt to send small msg to dest.
            sock.sendto(b"testing UDP. disregard this sorry.", 0, dest)
        except asyncio.CancelledError:  # pylint: disable=try-except-raise
            raise
        except (OSError, ConnectionError):
            # It's better to show a clear reason why the library won't work
            # than to silently fail.
            raise OSError("Error this library needs UDP support to work.") from None
        finally:
            if sock is not None:
                sock.close()

        _cached_netifaces = netifaces

        # Eagerly load the OS-default pseudo-interface so per-NIC is_default()
        # checks during the load_interfaces sweep don't race lazy init or
        # repeat the UDP-connect trick once per NIC. Deferred import avoids
        # the entrypoint <-> interface.load_interface module cycle.
        from .nic.interface import Interface  # pylint: disable=import-outside-toplevel
        if Interface.default is None:
            try:
                Interface.default = Interface("default")
            except OSError:
                log_exception()

        return netifaces


def aionetiface_setup_event_loop() -> None:
    """Patch the selector, configure the custom asyncio event loop policy,
    apply multiprocessing start-method, and install transport fatal-error patch.

    This function performs side-effectful global mutations. It is NOT called
    at import time; callers must invoke it explicitly before using the library.
    """
    # -----------------------------
    # Patch logic based on Python version
    # -----------------------------
    if sys.version_info >= (3, 7):
        # Modern Python
        SelectSelector._select = patched_select_modern
    else:
        # Older Python
        SelectSelector._select = patched_select_old

    # Force the multiprocessing start method to "spawn".
    #
    # Old shape only set spawn when get_start_method(allow_none=True)
    # returned None -- but the very first non-None query latches the
    # default ("fork" on Linux) into place, after which allow_none=True
    # also returns "fork" and the spawn upgrade silently never runs.
    # ProcessPoolExecutor then uses fork, which on Linux duplicates
    # parent FDs (asyncio selector, controlling-terminal TTY) into the
    # child. A child crash's cleanup can close those FDs in the parent
    # too -- observed: a same-NIC punch worker crashing closed bash's
    # stdin/stdout and the terminal window with it.
    #
    # force=True lets us override even when something already locked the
    # method. RuntimeError still fires if a child process tried to call
    # this from a non-main thread; the guard preserves that.
    if multiprocessing.get_start_method(allow_none=True) != "spawn":
        try:
            multiprocessing.set_start_method("spawn", force=True)
        except RuntimeError:
            # Already locked into a non-overridable context (rare;
            # happens when a frozen-bundle entry-point ran multiprocessing
            # before us). Nothing safe to do here.
            pass

    patch_asyncio_backports(CustomEventLoop)
    policy = asyncio.get_event_loop_policy()
    if not isinstance(policy, CustomEventLoopPolicy):
        asyncio.set_event_loop_policy(CustomEventLoopPolicy())

    # Monkey-patch the selector transport so a fatal transport error is logged
    # and the transport is force-closed rather than propagating up.
    def fatal_error(
        self, exc: BaseException, message: str = "Fatal error on transport"
    ) -> None:
        """Log and forcibly close the transport on a fatal async transport error."""
        er = {
            "message": message,
            "exception": exc,
            "transport": self,
            "protocol": self._protocol,
        }
        log(er)

        # Should be called from exception handler only.
        # self.call_exception_handler(er)
        self._force_close(exc)

    asyncio.selector_events._SelectorTransport._fatal_error = fatal_error


# NOTE: aionetiface_setup_event_loop() is NOT called at import time.
# Call it explicitly in your application entry point before using the library.


async def entrypoint_test() -> None:
    """Run aionetiface setup and print the netifaces instance to stdout."""
    out = await aionetiface_setup_netifaces()
    print(out)


if __name__ == "__main__":  # pragma: no cover
    async_run(entrypoint_test())
