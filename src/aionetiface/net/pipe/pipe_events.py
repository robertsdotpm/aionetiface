"""
Python's asyncio protocol classes seem to return human-readable
tuples that identify the packet's sender. At first glance this
seems to make sense. For people use the readable form of
addresses when working with them. But the network stack
needs it in binary form for routing. Hence, it will end up
having to convert an address to/from binary.

The problem is more complicated because IPv6 can have several representations of the same address in a readable form.
E.g. omitting zero portions with : or leading zero parts
of a segment. If you're trying to index a reply by an address it adds extra work because you have to normalize the address (for IPv6.)
Extra work means extra CPU.

Networking is generally supposed to be as fast as possible so
this design might not be ideal.

TODO: revisit drain and shutdown for close.
"""

import asyncio
import sys
from ...utility.utils import (
    fstr,
    log,
    log_exception,
    create_task,
    async_wrap_errors,
    run_handler,
    rm_done_tasks,
    cancel_task,
    cancel_tasks,
)
from ..net_defs import NET_CONF, SUB_ALL, IP4, IP6
from ...protocol.ack_udp import BaseACKProto
from .pipe_client import PipeClient
from .pipe_defs import TYPE_TCP_SERVER
from .pipe_utils import norm_client_tup, close_all_clients


"""
In Python's asyncio code you can use so-called 'protocol' classes
to receive messages from an endpoint or server and then handle
them in real time. This is a very elegant way to do things
because the event loop handles polling the sockets to check
if there's any new messages for you vs you doing the check
yourself using await. The drawback is the protocol-style way
of networking basically uses callbacks and by itself -- doesn't
mix well with the async way of doing things. But with some small
tweaks it is flexible enough to do whatever you want.
"""


class PipeEvents(BaseACKProto):
    """asyncio protocol class that routes datagrams and stream data to subscribers and callbacks."""

    def __init__(
        self, sock, route=None, loop=None, conf=None
    ):
        # Config.
        self.conf = conf if conf is not None else NET_CONF
        self.loop = loop

        # Socket of underlying connection.
        self.client_tup = None
        self.sock = sock
        self.tcp_clients = []
        self.tcp_server = None
        self.tcp_server_task = None
        self.endpoint_type = None
        self.proto = None

        # Used for TCP server awaitable.
        self.p_client_entry = 0  # Location of the pipe in client futures.
        self.p_client_insert = 0  # Last insert location in client futures.
        self.p_client_get = 0  # Offset that increases per await over the futures.
        self.client_futures = {0: asyncio.Future()}  # Table for TCP client pipes.

        # Bind / route.
        self.route = route

        # Can have pipes to other streams that it broadcasts to.
        self.pipes = []

        # List of other pipes that pipe to this.
        self.parent_pipes = []

        # Process messages in real time. Sets so duplicate-add (e.g.
        # when a plugin pre-populates pipe_events to win the
        # connection_made race AND the on_plugin_done callback later
        # tries to attach the same dispatcher) is a no-op instead of
        # double-firing every callback.
        self.msg_cbs = set()

        # Ran when a connection ends.
        self.end_cbs = set()

        # Ran when a connection is made.
        # For TCP this is a new connection.
        self.up_cbs = set()

        # List of tasks for send / recv / subscribe.
        """
        Coroutine references need to be saved or the garbage collector
        may clean them up. The list here is a generic list for async
        operations in motion as part of using this class -- possible
        operations like send / recv called via msg handlers may end
        up here and they're awaited for completion.
        """
        self.tasks = []

        # Tasks saved for running msg handlers.
        """
        When any message handlers that are coroutines are registered
        and run on a new message it's saved as a task in this list.
        These tasks aren't awaited for completion in close so
        that message handlers can call close themselves and not cause
        infinite waiting loops (their handler would never be 'done.'
        as it awaits on themself to finish.)
        Cleaned-up when a handler task is done.
        """
        self.handler_tasks = []

        # For unique messages if enabled.
        self.msg_ids = {}

        # Event fired when stream set.
        self.stream_ready = asyncio.Event()
        self.on_close = asyncio.Event()

        # Placeholders.
        self.transport = None
        self.stream = None
        self.is_ack = None
        self.is_ackable = None
        self.is_running = True
        self.proc_lock = None

        self.reachability = {IP4: {}, IP6: {}}

    # Indicates the type of endpoint this is.
    def set_endpoint_type(self, endpoint_type):
        """Record whether this pipe is a UDP server, UDP connection, TCP server, or TCP client."""
        self.endpoint_type = endpoint_type

    # Used for event-based programming.
    # Can execute code on new cons, dropped cons, and new msgs.
    def run_handlers(
        self,
        handlers,  # iterable of callables (set, list, tuple)
        client_tup=None,
        data=None,
    ):
        """Invoke every handler in handlers with client_tup and data, scheduling coroutines as tasks."""
        # Run any registered call backs on msg.
        self.handler_tasks = rm_done_tasks(self.handler_tasks)
        for handler in handlers:
            # Run the handler as a callback or coroutine.
            run_handler(self, handler, client_tup, data)

    def get_client_tup(self):
        """Return the remote peer address tuple, falling back to the local socket name."""
        # Get transport address.
        client_tup = None
        if self.sock is not None:
            # Use local socket details (for servers.)
            client_tup = self.sock.getsockname()

            # Try use remote peer info if it exists.
            try:
                client_tup = self.sock.getpeername()
            except OSError:
                pass

        return client_tup

    def add_tcp_client(self, client):
        """Register a new TCP client PipeEvents and resolve its corresponding awaitable Future."""
        # Save location of this client pipe in the table.
        client.p_client_entry = self.p_client_insert

        # Point to next entry in table and initialize it.
        self.p_client_insert = (self.p_client_insert + 1) % sys.maxsize
        self.client_futures[self.p_client_insert] = asyncio.Future()

        # Store this pipe in the Future.
        self.tcp_clients.append(client)
        self.client_futures[client.p_client_entry].set_result(client)

    async def make_awaitable(self):
        """Await the next accepted TCP client or return self for non-server endpoints."""
        if self.endpoint_type == TYPE_TCP_SERVER:
            bound = self.p_client_insert + 1
            for p in range(0, bound):
                # Get reference to the current future to await on.
                cur_p_get = (self.p_client_get + p) % bound

                # Skip empty entries deleted on connection lost.
                if self.client_futures[cur_p_get] is None:
                    continue

                # Increment the pointer to the next future in line.
                # This sets it up for the next await call to work.
                # Only increment it if the current location is taken.
                if self.client_futures[cur_p_get].done():
                    self.p_client_get = (cur_p_get + 1) % bound

                # Await on the future at the head of the futures.
                return await self.client_futures[cur_p_get]

            raise AssertionError("Could not find awaitable future accept().")
        else:
            # TCP con -> one pipe so no reason to await it.
            # UDP server or con -> multiplex so one pipe for everything.
            return self

    def __await__(self):
        return self.make_awaitable().__await__()

    def set_tcp_server(self, server):
        """Store the asyncio Server object as both the transport and tcp_server reference."""
        self.transport = server
        self.tcp_server = server

    def set_tcp_server_task(self, task):
        """Hold a reference to the serve_forever task so the garbage collector cannot kill it."""
        self.tcp_server_task = task

    def set_ack_handlers(
        self, is_ack, is_ackable
    ):
        """Register the is_ack and is_ackable predicates for reliable UDP ACK processing."""
        self.is_ack = is_ack
        self.is_ackable = is_ackable
        return self

    def add_pipe(self, pipe):
        """Link pipe as an outbound relay target and register self as its parent."""
        self.pipes.append(pipe)
        pipe.parent_pipes.append(self)
        return self

    def del_pipe(self, pipe):
        """Remove pipe from the outbound relay list."""
        if pipe in self.pipes:
            self.pipes.remove(pipe)

        return self

    def add_msg_cb(self, msg_cb):
        """Add msg_cb to the set of callbacks invoked on every incoming message (idempotent)."""
        self.msg_cbs.add(msg_cb)
        return self

    def del_msg_cb(self, msg_cb):
        """Remove msg_cb from the message callback set."""
        self.msg_cbs.discard(msg_cb)
        return self

    def add_up_cb(self, up_cb):
        """Add up_cb to the set of callbacks invoked when a new connection is established."""
        self.up_cbs.add(up_cb)
        return self

    def del_up_cb_cb(self, up_cb):
        """Remove up_cb from the connection-established callback set."""
        self.up_cbs.discard(up_cb)
        return self

    def add_end_cb(self, end_cb):
        """Add end_cb to the set of callbacks invoked when a connection is lost."""
        was_present = end_cb in self.end_cbs
        self.end_cbs.add(end_cb)

        # Make sure it runs if this is already closed -- but only fire it
        # the first time it's added so a duplicate add doesn't double-run.
        if not self.is_running and not was_present:
            self.run_handlers([end_cb])

        return self

    def del_end_cb(self, end_cb):
        """Remove end_cb from the connection-lost callback set."""
        self.end_cbs.discard(end_cb)
        return self

    # Called only once for UDP.
    def connection_made(self, transport):
        """Initialise the stream object and signal readiness when the transport is established."""
        if self.stream is None:
            # Record the endpoint.
            if transport is not None:
                self.transport = transport
                self.client_tup = self.get_client_tup()

            # Set stream object for doing I/O.
            self.stream = PipeClient(self, loop=self.loop)
            self.stream_ready.set()

        # Process messages using any registered handlers.
        self.run_handlers(self.up_cbs)

    # Socket closed manually or shutdown by other side.
    def connection_lost(self, exc):
        """Clean up parent-pipe links, run end callbacks, and set the on_close event."""
        super().connection_lost(exc)

        # Remove self from any parent pipes.
        for pipe in self.parent_pipes:
            pipe.del_pipe(self)

        # Execute any cleanup handlers.
        self.run_handlers(self.end_cbs, self.client_tup)
        self.on_close.set()

    def route_msg(self, data, client_tup):
        """Relay data to linked pipes, run message callbacks, and deliver to subscriptions."""
        # No data to route.
        if not data:
            return

        # Route messages to any pipes.
        for pipe in self.pipes:
            task = create_task(async_wrap_errors(pipe.send(data, pipe.sock.getpeername())))

            self.tasks.append(task)

        # Process messages using any registered handlers.
        self.run_handlers(self.msg_cbs, client_tup, data)

        # Add message to any interested subscriptions.
        # Matching pattern for host is in bytes so
        # there is a need to convert ip to bytes.
        self.stream.add_msg(data, (client_tup[0], client_tup[1]))

    def handle_data(self, data, client_tup):
        """Process a received payload: handle ACKs, deduplicate if enabled, then route."""
        # Convert data to bytes.
        if isinstance(data, bytearray):
            data = bytes(data)

        # Norm IP.
        client_tup = norm_client_tup(client_tup)

        # Ack UDP msg if enabled.
        if self.is_ack and self.is_ackable:
            """
            Sends an ACK down the stream if it's a message that needs an ACK.
            Clients that use the 'reliable' UDP functions over a specific
            protocol provide their own functions for returning these ACKs.
            Hence the code works with any protocol.
            """
            did_ack, payload = self.stream.handle_ack(
                data,
                self.is_ack,
                self.is_ackable,
                lambda buf: self.stream.send(buf, client_tup),
            )

            """
            The Stream protocol class does not route back
            messages that are ACKs to messages we sent. Otherwise
            a sender might see a returned ACK and get into a loop
            trying to ACK it themself. It's a control message so
            there's no real reason to route them to recv.
            """
            if not did_ack:
                return
            # Strip the header portion out.
            data = payload

        # Supports unique messages.
        if self.conf["enable_msg_ids"]:
            if not self.is_unique_msg(self.stream, data, client_tup):
                return

        # Route message to stream.
        self.route_msg(data, client_tup)

    def error_received(self, exp):
        """Log a non-fatal transport error received from the asyncio event loop."""
        log_exception()

    # UDP packets.
    def datagram_received(self, data, client_tup):
        """Called by asyncio when a UDP datagram arrives; forwards to handle_data."""
        # log(fstr("Base proto recv udp = {0} {1}", (client_tup, data,)))
        if self.transport is None:
            log(fstr("Skipping process data cause transport none 1."))
            return

        self.handle_data(data, client_tup)

    # Single TCP connection.
    def data_received(self, data):
        """Called by asyncio when TCP stream data arrives; extracts peer address and forwards."""
        try:
            # log(fstr("Base proto recv tcp = {0}", (data,)))
            if self.transport is None:
                log(fstr("Skipping process data cause transport none 2."))
                return

            client_tup = self.transport.get_extra_info("socket").getpeername()
            self.handle_data(data, client_tup)
        except (OSError, ConnectionError):
            log_exception()

    async def close(self, force=False, keep_clients=False):
        if not self.is_running:
            return
        self.is_running = False

        """
        If this is a transport for a TCP server its important to close
        it first before closing tcp_clients. Otherwise, new clients may
        be accepted while TCP clients are added to the server and
        the close code may end up missing them.
        """
        if self.sock:
            loop = asyncio.get_running_loop()
            if hasattr(loop, "await_fd_close"):
                on_close = loop.await_fd_close(self.sock)
            else:
                on_close = None

            if self.transport is not None:
                if force:
                    # abort() is not available on asyncio.Server (TCP server transport).
                    if hasattr(self.transport, "abort"):
                        self.transport.abort()
                    else:
                        self.transport.close()
                else:
                    # Send data pending in socket buffer.
                    if hasattr(self.transport, "drain"):
                        await self.transport.drain()

                    # Signal EOF with clean shutdown.
                    # can_write_eof() raises NotImplementedError on UDP transports,
                    # and Server objects (stored as transport for TCP servers) don't
                    # have this method at all.
                    try:
                        if self.transport.can_write_eof():
                            self.transport.write_eof()
                    except (NotImplementedError, AttributeError):
                        pass

                    # Schedule the transport to close.
                    self.transport.close()
                await asyncio.sleep(0)

            # Await close if it's possible to do so.
            # Use wait_for so UDP transports (not registered with the selector)
            # don't hang here forever — pipe_utils.py uses the same pattern.
            if on_close:
                try:
                    await asyncio.wait_for(on_close, timeout=2.0)
                except asyncio.TimeoutError:
                    pass

        """
        If it's a TCP server close TCP client cons.
        """
        if self.tcp_clients and not keep_clients:
            await close_all_clients(self.tcp_clients, timeout=1.0)
            await asyncio.sleep(0)

        await cancel_task(self.tcp_server_task)
        await cancel_tasks(self.tasks)

        # No longer running (is_running was already set False at entry).
        self.transport = None
        self.sock = None
        self.tcp_server = None
        self.tcp_server_task = None
        self.tcp_clients = []
        self.tasks.clear()
        if self.proc_lock is not None:
            self.proc_lock.release()

    # Return a matching message, async, non-blocking.
    async def recv(
        self, sub=None, timeout=2, full=False
    ):
        """Delegate to the stream's recv, waiting for a message matching sub."""
        if sub is None:
            sub = SUB_ALL
        return await self.stream.recv(sub, timeout, full)

    async def recv_n(self, n, sub=None):
        """Receive and accumulate messages until at least n bytes are collected."""
        if sub is None:
            sub = SUB_ALL
        return await self.stream.recv_n(n, sub)

    async def send(
        self, data, dest_tup=None
    ):
        """Send data to dest_tup (or the stored destination) via the stream."""
        if not self.is_running or self.stream is None:
            return 0
        dest_tup = dest_tup or self.stream.dest_tup
        return await self.stream.send(data, dest_tup)

    # Sync subscribe to a message.
    # Easy way to get a message from sync code too.
    def subscribe(
        self, sub=None, handler=None
    ):
        """Register a subscription on the stream and return the subscription offset."""
        if sub is None:
            sub = SUB_ALL
        return self.stream.subscribe(sub, handler)

    def unsubscribe(self, sub):
        """Remove the subscription matching sub from the stream."""
        return self.stream.unsubscribe(sub)

    # Echo client just for testing.
    async def echo(self, msg, dest_tup):
        """Send an ECHO-prefixed message back to dest_tup for testing purposes."""
        buf = bytearray().join([b"ECHO ", msg, b"\n"])
        await self.send(buf, dest_tup)

    async def safe_write(self, data):
        """Write data to the transport and drain, raising ConnectionError if the socket closes."""
        # 1. Check BEFORE writing
        if (
            self.on_close.is_set()
            or self.transport is None
            or self.transport.is_closing()
        ):
            raise ConnectionError("Attempted to write to a closed socket.")

        # 2. Perform the write
        self.transport.write(data)

        await asyncio.sleep(0)
        if self.on_close.is_set():
            raise ConnectionError("Socket closed during flush.")

        # 3. Simple Drain (Wait for buffer to clear)
        # We wait until the transport buffer size is 0.
        # Snapshot transport each iteration: close() can set self.transport = None
        # (pipe_events.py close(), line ~425) while we're suspended at the sleep
        # below, causing AttributeError if we access self.transport directly in
        # the while condition.  Always check for None before dereferencing.
        while True:
            t = self.transport
            if t is None or self.on_close.is_set():
                raise ConnectionError("Socket closed during flush.")
            if t.get_write_buffer_size() == 0:
                break
            await asyncio.sleep(0.01)  # Small yields to the loop

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()
        return False
