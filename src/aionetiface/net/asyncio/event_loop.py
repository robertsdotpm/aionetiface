import asyncio
import socket
import selectors
import traceback
from ...utility.utils import *

# Map: FD -> Future object
CLOSE_FUTURES = {}

class ProxySelector:
    """A wrapper around the actual selector object to intercept unregister calls."""
    
    def __init__(self, selector_instance, loop):
        self.selector = selector_instance
        self.loop = loop
        self.select = selector_instance.select
        self.close = selector_instance.close
        self.register = selector_instance.register
        self.get_map = selector_instance.get_map
        self.get_key = selector_instance.get_key

    def maybe_signal_removal(self, fd: int, events: int, data: tuple) -> None:
        """Helper to signal the future if the FD is being completely unregistered."""
        
        # Check if the FD's future exists
        if fd not in CLOSE_FUTURES:
            #CLOSE_FUTURES[fd] = self.loop.create_future()
            return

        # In the context of a fully-removed item:
        if events == 0 and data is None:
            future = CLOSE_FUTURES.pop(fd)
            if not future.done():
                self.loop.call_soon(future.set_result, True)

    def unregister(self, fd):
        """Intercepts the complete removal of the FD."""
        # The FD is being completely removed. Signal the removal future.
        self.maybe_signal_removal(fd, 0, None)
        return self.selector.unregister(fd)
    
    def modify(self, fd, events, data=None):
        """Intercepts modification, checking if FD is effectively unregistered."""
        if events == 0:
            # FD modified to watch for 0 events, it's equivalent to unregister.
            self.maybe_signal_removal(fd, 0, None)
        elif events != 0:
            # NOTE: This is tricky, the SelectorEventLoop mostly handles this.
            # We focus on the unregister/events=0 case for reliability.
            pass

        return self.selector.modify(fd, events, data)

class CustomEventLoop(asyncio.SelectorEventLoop):
    """Event loop that uses the ProxySelector."""
    
    def __init__(self, selector=None):
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

        # --- Begin added code for clock support ---
        # Internal set of registered clocks
        clocks = set()


        # Overwrite the sleep method
        async def sleep(async_sleep, seconds, *args, **kwargs):
            result = await async_sleep(seconds, *args, **kwargs)
            
            # Advance all registered clocks by the sleep duration
            for clock in clocks:
                continue
                clock.advance(seconds)

            return result

        self.sleep = sleep
        self.clocks = clocks

    # Add your public API method back (using the global map from the proxy)
    def await_fd_close(self, sock: socket) -> asyncio.Future:
        fd = sock.fileno()
        if fd == -1:
            log("-1 passed to await_fd_close()!")
            f = self.create_future()
            f.set_result(True)
            return f

        if fd not in CLOSE_FUTURES:
            CLOSE_FUTURES[fd] = self.create_future()
            
        return CLOSE_FUTURES[fd]

    # --- Begin added methods for clock registration ---
    def register_clock(self, clock):
        """Register a clock instance to be advanced on sleeps."""
        self.clocks.add(clock)

    def unregister_clock(self, clock):
        """Unregister a clock instance."""
        self.clocks.discard(clock)
    # --- End added methods ---

class CustomEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    @staticmethod
    def exception_handler(self, context):
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
            buf.append("Occurred in " + filename + ", function " + funcname + ", line " + str(lineno))

        # Log full traceback
        buf.append("Full traceback:")
        buf.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))

        # Write all at once
        log("\n".join(buf))

    @staticmethod
    def loop_setup(loop):
        loop.set_debug(False)
        loop.set_exception_handler(CustomEventLoopPolicy.exception_handler)
        loop.default_exception_handler = CustomEventLoopPolicy.exception_handler

    def new_event_loop(self):
        selector = selectors.SelectSelector()
        loop = CustomEventLoop(selector)
        CustomEventLoopPolicy.loop_setup(loop)
        return loop