"""TCP-specific event handlers for the pipe abstraction."""
import asyncio
import sys
from typing import Any, Optional
from ...utility.utils import fstr, log, log_exception
from ..net_defs import NET_CONF
from .pipe_events import PipeEvents
from .pipe_defs import TYPE_TCP_CLIENT, aionetiface_fds


PY_13_OR_LATER = sys.version_info >= (3, 13)

"""
StreamReaderProtocol provides a way to "translate" between
Protocol and StreamReader. Mostly we're interested in having
a protocol class for TCP that can handle messages as they're
ready as opposed to having to poll ourself. Encapsulates
a client connection to a TCP server in a BaseProto object.
"""


class TCPClientProtocol(asyncio.StreamReaderProtocol):
    """StreamReaderProtocol subclass that bridges each TCP client connection into a PipeEvents."""

    def __init__(
        self, stream_reader: Any, pipe_events: Any, loop: Any, conf: Optional[Any] = None
    ) -> None:
        if PY_13_OR_LATER:
            super().__init__(stream_reader)
        else:
            # Keep the old 3.5–3.12 set_streams hack
            def set_streams(_reader, _writer):
                if not hasattr(self, "_stream_reader"):
                    self._stream_reader = _reader

                if not hasattr(self, "_stream_writer"):
                    self._stream_writer = _writer

                return 1

            super().__init__(stream_reader, set_streams, loop=loop)

        # PipeEvents is created once before create_tcp_server -- but
        # it's not used as an event-driven protocol class directly.
        # It acts as a container/API; this class passes events into it
        # for TCP-based client messages.
        if conf is None:
            conf = NET_CONF
        self.pipe_events = pipe_events
        self.loop = loop

        # Will represent us.
        # Servers route above will be reused for this.
        self.client_events = None
        self.client_offset = 0

        # Main class variables.
        self.sock = None
        self.transport = None
        self.remote_tup = None
        self.conf = conf

    # StreamReaderProtocol has a bug: eof_received doesn't properly return
    # False. This override is a patch.
    def eof_received(self) -> bool:
        """Feed EOF into the stream reader and return False to close the transport immediately."""
        # self.transport.pause_reading()
        reader = self._stream_reader
        if reader is not None:
            reader.feed_eof()

        return False

    def connection_made(self, transport: Any) -> None:
        """Set up the client PipeEvents, register it with the server, and wire up the stream writer."""
        if PY_13_OR_LATER:
            # In 3.13 StreamWriter.__init__ dropped the loop parameter.
            writer = asyncio.StreamWriter(transport, self, self._stream_reader)
            self._stream_writer = writer

        # Wrap this connection in a BaseProto object.
        self.transport = transport
        self.sock = transport.get_extra_info("socket")
        aionetiface_fds.add(self.sock)

        self.remote_tup = self.sock.getpeername()
        self.client_events = PipeEvents(
            sock=self.sock, route=self.pipe_events.route, conf=self.conf, loop=self.loop
        )

        # Log connection details.
        log(
            fstr(
                "New TCP client l={0}, r={1}",
                (
                    self.sock.getsockname(),
                    self.remote_tup,
                ),
            )
        )

        # Setup stream object.
        self.client_events.set_endpoint_type(TYPE_TCP_CLIENT)
        self.client_events.msg_cbs = self.pipe_events.msg_cbs
        self.client_events.end_cbs = self.pipe_events.end_cbs
        self.client_events.up_cbs = self.pipe_events.up_cbs
        self.client_events.connection_made(transport)
        self.client_events._stream_writer = self._stream_writer

        # Record destination.
        self.client_events.stream.set_dest_tup(self.remote_tup)

        # Record instance to allow cleanup in server.
        self.pipe_events.add_tcp_client(self.client_events)

        # Setup handle for writing.
        super().connection_made(transport)
        self.client_events.stream.set_handle(
            self._stream_writer,
            # Index writers by peer connection.
            self.remote_tup,
        )

    # If close was called on a pipe on a server then clients will already be closed.
    # So this code will have no effect.
    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Clean up the client entry, run disconnect handlers, and signal the on_close event."""
        super().connection_lost(exc)

        # Cleanup client futures entry.
        p_client_entry = self.client_events.p_client_entry
        client_future = self.pipe_events.client_futures[p_client_entry]
        if client_future.done():
            del self.pipe_events.client_futures[p_client_entry]

        # Run disconnect handlers if any set.
        client_tup = self.remote_tup
        self.client_events.run_handlers(self.client_events.end_cbs, client_tup)

        # Set on close event.
        self.client_events.on_close.set()

        # Close its client socket and transport.
        """
        Will lead to issues iterating on closing TCP clients?
        try:
            if self.client_events in self.pipe_events.tcp_clients:
                self.pipe_events.tcp_clients.remove(self.client_events)
        except Exception:
            log_exception()
        """

        """
        Transport should be closed if this is called?
        try:
            self.transport.close()
            self.transport = None
        except Exception:
            log_exception()
        """

        # Remove this as an object to close and manage in the server.
        # super().connection_lost(exc)

    def error_received(self, exp: Exception) -> None:
        """Log any transport-level error received for this connection."""
        log_exception()

    def data_received(self, data: bytes) -> None:
        """Forward received bytes to the client PipeEvents message handler."""
        log(fstr("Base proto recv tcp client = {0}", (data,)))
        # This just adds data to reader which we are handling ourselves.
        # super().connection_lost(exc)
        if self.client_events is None:
            return

        if not len(self.client_events.msg_cbs):
            log("No msg cbs registered for inbound message in hacked tcp server.")

        self.client_events.handle_data(data, self.remote_tup)


# Returns a hacked TCP server object
async def create_tcp_server(
    sock: Any,
    pipe_events: Any,
    *,
    loop: Optional[Any] = None,
    conf: Optional[Any] = None,
    **kwds
) -> Any:
    """Create and return an asyncio TCP server that uses TCPClientProtocol for each new connection."""
    if conf is None:
        conf = NET_CONF
    # Main vars.
    loop = loop or asyncio.get_event_loop()

    def factory():
        """Instantiate a fresh StreamReader and TCPClientProtocol for each incoming TCP connection."""
        if sys.version_info >= (3, 10):
            reader = asyncio.StreamReader(limit=conf["reader_limit"])
        else:
            reader = asyncio.StreamReader(limit=conf["reader_limit"], loop=loop)
        return TCPClientProtocol(reader, pipe_events, loop, conf)

    # Call the regular create server func with custom protocol factory.
    server = await loop.create_server(factory, sock=sock, **kwds)

    return server
