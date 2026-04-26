"""Event-loop creation and management helpers."""
import asyncio
import selectors
import traceback
from typing import Any, Dict, Optional
from ...utility.utils import *


# Map: id(socket_object) -> Future
# We use id() because FDs are recycled, but Python object memory IDs
# are unique for the lifetime of that specific socket object.
CLOSE_FUTURES = {}


class ProxySelector:
    """A wrapper around elector object to intercept unregister calls."""

    def __init__(self, selector_instance: Any, loop: Any) -> None:
        self.selector = selector_instance
        self.loop = loop

        # Proxy standard methods. select is wrapped (not bound directly)
        # so we can catch WinError 10038 ("not a socket") that fires on
        # older Windows (XP) when an FD is closed externally between
        # transport.close() and the next selector.select(). Bare
        # propagation kills the loop; surgical recovery by unregistering
        # the bad FD and retrying keeps the rest of the registered
        # sockets functional.
        self.close = selector_instance.close
        self.register = selector_instance.register
        self.get_map = selector_instance.get_map
        self.get_key = selector_instance.get_key

    def select(self, timeout: Any = None) -> Any:
        """Forward to the underlying selector, recovering from stale-FD errors.

        On Windows XP (and other older Winsock stacks) a closed socket
        whose FD hasn't been unregistered yet causes
        ``select.select(...)`` to raise ``OSError: [WinError 10038]``
        ("operation attempted on something that is not a socket").
        Asyncio doesn't catch this and the whole event loop dies --
        symptom we hit during ``Nickname.start()`` running parallel
        TCP connect / close cycles via ``asyncio.gather``.

        Recovery: walk every registered fd, validate each one's
        fileobj.fileno() in isolation (which raises OSError if the
        underlying socket is gone), unregister the dead ones, and
        retry the full select. Single pass, no nested select() calls
        so a healthy registered FD can't be misidentified as bad.
        """
        try:
            return self.selector.select(timeout)
        except OSError as exc:
            winerror = getattr(exc, "winerror", None)
            errno = getattr(exc, "errno", None)
            # 10038 is WSAENOTSOCK on Windows. EBADF (9) is the closest
            # POSIX analogue; cover both for safety on weird stacks.
            if winerror not in (10038,) and errno not in (9,):
                raise

            # Walk the fd_map and evict any whose underlying file
            # object's fileno() raises -- those are the closed-but-
            # still-registered ones. Healthy FDs pass fileno() and
            # stay put.
            bad_fds = []
            try:
                fd_map = dict(self.selector.get_map())
            except Exception:  # pylint: disable=broad-except
                fd_map = {}
            for fd, key in fd_map.items():
                fileobj = getattr(key, "fileobj", None)
                target = fileobj if fileobj is not None else fd
                try:
                    if hasattr(target, "fileno"):
                        target.fileno()
                except (OSError, ValueError):
                    bad_fds.append(fd)

            for fd in bad_fds:
                try:
                    self.maybe_signal_removal(fd, 0, None)
                    self.selector.unregister(fd)
                except (KeyError, ValueError, OSError):
                    pass

            # Retry once. If it fails again, propagate -- something
            # other than a stale FD is wrong.
            return self.selector.select(timeout)

    def maybe_signal_removal(self, fd: Any, events: int, data: Any) -> None:
        """Helper to signal if FD is being completely unregistered."""

        # Check if the FD's future exists in the global map
        if fd not in CLOSE_FUTURES:
            return

        # In the context of a fully-removed item (events=0 or explicit unregister):
        if events == 0 and data is None:
            # Pop entries for FD to clear the state for potential FD recycling
            entries = CLOSE_FUTURES.pop(fd, [])
            for sock_id, future in entries:
                if not future.done():
                    # Use call_soon to set result in the next tick to avoid
                    # potential recursion issues during selector processing
                    self.loop.call_soon(future.set_result, True)

    def unregister(self, fd: Any) -> Any:
        """Intercepts the complete removal of the FD."""
        # CLOSE_FUTURES is keyed by integer fd.  Convert a socket/file object
        # to its integer fd before the lookup so the future is actually found.
        real_fd = fd if isinstance(fd, int) else fd.fileno()
        self.maybe_signal_removal(real_fd, 0, None)
        return self.selector.unregister(fd)

    def modify(self, fd: Any, events: int, data: Optional[Any] = None) -> Any:
        """Intercepts modification, checking if FD is effectively unregistered."""
        # fileobj/fd check
        real_fd = fd if isinstance(fd, int) else fd.fileno()

        if events == 0:
            # In many SelectorLoop implementations, modify(fd, 0) is the
            # precursor to a full close or a complete stop of the transport.
            self.maybe_signal_removal(real_fd, 0, None)

        return self.selector.modify(fd, events, data)


class CustomEventLoop(asyncio.SelectorEventLoop):
    """Event loop that uses the ProxySelector."""

    def create_future(self) -> Any:
        # loop.create_future() was added in Python 3.5.1; 3.5.0 lacks it.
        # On 3.5.1+ the super() call goes to BaseEventLoop.create_future().
        try:
            return super(CustomEventLoop, self).create_future()
        except AttributeError:
            return asyncio.Future(loop=self)

    def __init__(self, selector: Optional[Any] = None) -> None:
        # Determine the default selector class if none is provided
        if selector is None:
            selector_cls = selectors.DefaultSelector
            # Create an instance of the *real* selector
            real_selector = selector_cls()
        else:
            # Assume 'selector' is the actual selector instance
            real_selector = selector

        # 1. Wrap the real selector with our proxy
        proxy_selector = ProxySelector(real_selector, self)

        # 2. Initialize the base class with our proxy
        # The base SelectorEventLoop expects a selector object here.
        super().__init__(proxy_selector)

    def close(self) -> None:
        """
        Override to drain CLOSE_FUTURES when the loop is closed.

        If the loop is torn down before every transport has been properly
        unregistered from the selector (e.g. after task-cancellation during
        shutdown), awaiter futures registered via await_fd_close() would
        otherwise leak in the module-level CLOSE_FUTURES dict indefinitely.
        Resolve them so any remaining awaiters unblock, then remove the
        entries to reclaim memory.
        """
        for fd, entries in list(CLOSE_FUTURES.items()):
            for _sock_id, fut in entries:
                if not fut.done():
                    try:
                        fut.set_result(True)
                    except asyncio.InvalidStateError:
                        pass
            CLOSE_FUTURES.pop(fd, None)
        super().close()

    # Add your public API method back (using the global map from the proxy)
    def await_fd_close(self, sock: Any) -> Any:
        """Return a Future that resolves once the selector unregisters this socket's file descriptor."""
        # Ensure we are not returning a coroutine
        fd = sock.fileno()
        if fd == -1:
            f = self.create_future()  # Use self.loop or self
            f.set_result(True)
            return f

        fut = self.create_future()
        sock_id = id(sock)

        if fd not in CLOSE_FUTURES:
            CLOSE_FUTURES[fd] = []

        CLOSE_FUTURES[fd].append((sock_id, fut))
        return fut


class CustomEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    """Asyncio event loop policy that installs CustomEventLoop and a structured exception handler."""

    @staticmethod
    def exception_handler(self: Any, context: Dict[str, Any]) -> None:
        """
        Custom asyncio exception handler.
        Logs exception type, message, and the line number where it occurred.
        Compatible with Python 3.5+.
        """
        buf = []

        buf.append("Exception handler in custom event loop")
        exc = context.get("exception")
        if exc is None:
            # No exception object, log the message
            msg = context.get("message", "Unknown exception")
            buf.append("No exception object, context message: " + str(msg))
            log("\n".join(buf))
            return

        # Log the exception type and message
        buf.append("Exception type: " + str(type(exc).__name__))
        buf.append("Exception message: " + str(exc))

        # Extract traceback and log the last frame (where exception occurred)
        tb = exc.__traceback__
        if tb is not None:
            while tb.tb_next:
                tb = tb.tb_next
            frame = tb.tb_frame
            lineno = tb.tb_lineno
            filename = frame.f_code.co_filename
            funcname = frame.f_code.co_name
            buf.append(
                "Occurred in "
                + filename
                + ", function "
                + funcname
                + ", line "
                + str(lineno)
            )

        # Log full traceback
        buf.append("Full traceback:")
        buf.append(
            "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        )

        # Write all at once
        log("\n".join(buf))

    @staticmethod
    def loop_setup(loop: Any) -> None:
        """Apply standard debug and exception-handler settings to a freshly created loop."""
        loop.set_debug(False)
        loop.set_exception_handler(CustomEventLoopPolicy.exception_handler)
        # Note: do NOT assign to loop.default_exception_handler here.
        # asyncio calls set_exception_handler callbacks as handler(loop, context)
        # but calls default_exception_handler as handler(context) — one argument,
        # not two.  Assigning our staticmethod (which needs two args) would cause a
        # TypeError the first time the default handler is invoked directly.

    def new_event_loop(self) -> CustomEventLoop:
        """Create, configure, and return a new CustomEventLoop with the ProxySelector installed."""
        selector = selectors.SelectSelector()
        loop = CustomEventLoop(selector)
        CustomEventLoopPolicy.loop_setup(loop)
        return loop
