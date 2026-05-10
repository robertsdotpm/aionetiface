"""
- pipe_open allows multiple encoding forms to be used for the IP
field. But bytes is a little unclear. Is it the raw bytes of
an IP address or is it a human-readable IP in ASCII? I
decided to default to the latter otherwise devs. But you
can still pass in ints or IPRanges to use raw IPs. With
ints just make sure there is a route alongside it because
the address family is needed to disambiguate whether the
int is a short IPv6 or an IPv4.

- theres a bug on ancient operating systems (Windows Vista)
where await sock_event with wait_for can crash the event loop.
The fix has been merged in >= 3.7.5 which also works on Vista.
I wasn't even able to get Python 3 to run on XP so for now it
isn't supported. Trying to merge Python fixes for older OSes
isn't a priority so these users should be told to upgrade
Python versions if they get bugs with the event loop.

https://bugs.python.org/issue34795
"""

import asyncio
import sys
from ...utility.utils import (
    log,
    log_exception,
    fstr,
    async_wrap_errors,
    get_running_loop,
)
from ..net_defs import (
    NET_CONF,
    SUB_ALL,
    UDP,
    RUDP,
    TCP,
    IP4,
    IP6,
    VALID_LOOPBACKS,
    VALID_ANY_ADDR,
)
from .pipe_events import PipeEvents
from .pipe_client import PipeClient
from .pipe_tcp_events import TCPClientProtocol
from .pipe_utils import norm_client_tup, tup_to_sub
from ..address import Address
from ..ip_range import IPRange, IPR, ipr_norm
from ..asyncio.asyncio_patches import create_datagram_endpoint
from .pipe_tcp_events import create_tcp_server
from ..socket import socket_factory
from .pipe_defs import (
    TYPE_UDP_CON,
    TYPE_UDP_SERVER,
    TYPE_TCP_CON,
    TYPE_TCP_SERVER,
    aionetiface_fds,
)
from ..asyncio.create_udp_fallback import PolledDatagramTransport, UdpPoller
from ..asyncio.event_loop import CustomEventLoop



class Pipe:
    """High-level abstraction over a TCP or UDP socket with async send/recv and lifecycle management."""

    def __init__(
        self,
        proto,
        dest=None,
        route=None,
        sock=None,
        conf=None,
    ):
        self.set_nic_and_route(route)
        self.proto = proto
        self.sock = sock
        self.dest = dest
        self.pipe_events = None
        self.conf = conf if conf is not None else NET_CONF
        self.owns_socket = sock is None
        if sock is not None:
            log("Warning: externally provided socket will not be closed by Pipe")

        self._opened = False
        self._closed = False

    async def connect(self, msg_cb=None, up_cb=None):
        """
        Opens the pipe, resolves route/dest, creates socket and PipeEvents.
        Safe to call multiple times.
        """
        if self._opened:
            return self

        do_connect = self.sock is None
        try:
            await self.resolve_route_and_dest()
            await self.create_or_use_socket()
            if do_connect:
                await self.tcp_client_connect_if_needed()

            await self.setup_pipe_events(msg_cb, up_cb)
            self._opened = True
        except asyncio.CancelledError:
            self.cleanup_on_error()
            raise
        except (
            OSError,
            ConnectionError,
            asyncio.TimeoutError,
            RuntimeError,
        ):
            # defensive cleanup
            self.cleanup_on_error()
            raise

        return self

    async def close(self, force=False, keep_clients=False):
        """Close the underlying pipe_events transport and release associated resources."""
        if self.pipe_events is not None:
            await self.pipe_events.close(force=force, keep_clients=keep_clients)

    async def accept(self):
        """Wait for and return the next incoming TCP client pipe from a server socket."""
        if self.pipe_events is not None:
            return await self.pipe_events.make_awaitable()

    # Pretend to be a pipe_client.
    def __getattr__(self, name):
        """
        Redirect attribute access to self.pipe_events if it exists.
        Called only if the attribute doesn't exist on self.
        """
        if self.pipe_events is not None:
            try:
                return getattr(self.pipe_events, name)
            except AttributeError:
                pass

        raise AttributeError("'Pipe' object has no attribute " + str(name))

    # -----------------------------
    # Async context manager support
    # -----------------------------
    async def __aenter__(self):
        # Simply return self; connect() must be awaited before using async with
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    # -----------------------------
    # Wrapper to allow 'async with Pipe(...).session()'
    # -----------------------------
    def session(self, msg_cb=None, up_cb=None):
        """
        Returns an awaitable object that opens the pipe and supports async with.
        """
        pipe = self

        class _PipeAwaitableContext:
            """Awaitable context manager returned by Pipe.session() to open and auto-close a pipe."""

            def __init__(self):
                self._pipe = pipe

            def __await__(self):
                return pipe.connect(msg_cb, up_cb).__await__()

            async def __aenter__(self):
                # Ensure pipe is fully opened
                await pipe.connect(msg_cb, up_cb)
                return pipe

            async def __aexit__(self, exc_type, exc, tb):
                await pipe.close()

        return _PipeAwaitableContext()

    # -----------------------------
    # Public helper methods
    # -----------------------------
    async def get_loop(self):
        """Return the running asyncio event loop, using conf['loop'] if provided."""
        if self.conf.get("loop") is not None:
            return self.conf["loop"]()
        return get_running_loop()

    def set_nic_and_route(self, unknown):
        """Set self.nic and self.route from an Interface, a Route, or None (defaults to default NIC)."""
        from ...nic.interface import Interface  # pylint: disable=cyclic-import

        self.route = None
        self.nic = None
        if unknown:
            if isinstance(unknown, Interface):
                self.nic = unknown
            else:
                self.nic = unknown.interface
                self.route = unknown
        else:
            self.nic = Interface("default")

    async def resolve_route_and_dest(self):
        """Bind the route and resolve the destination address, updating self.route and self.dest."""
        self.route = await self.resolve_route(self.route)

        # By this point there's a route + nic.
        assert self.route and self.nic

        self.dest = await self.resolve_dest(self.dest, self.conf)

    async def resolve_route(self, route):
        """
        Resolves the route to bind the socket.
        Covers the case where a network Interface is passed instead of a route.
        In that case, just use the first available route at first supported AF.
        """
        if route is None:
            # For legacy code that passes Interface (or AFGroup): pick the
            # first supported AF and fetch its route. Interface.supported()
            # returns the AFs in priority order; AFGroup.supported() returns
            # the AFs the group was constructed with in insertion order.
            # Either way, [0] reproduces the previous "first available
            # route at first supported AF" semantics without depending on
            # the now-unavailable zero-arg `nic.route()` form.
            af = self.nic.supported()[0]
            route = self.nic.route(af)

        # Routes all need to be bound.
        if not route.resolved:
            log("Resolve route received unbound route.")
            await route.bind()

        return route

    async def resolve_dest(self, dest, conf):
        """
        Converts dest into an Address instance if necessary.
        Supports IP:port tuples, int IPs, bytes, IPRange, or Address instances.
        """
        if dest is None:
            return None

        # For IPv6: dest tuples still need an interface to work correctly.
        if isinstance(dest, (list, tuple)):
            ip, port = dest

            # Normalize IPRange
            if isinstance(ip, IPRange):
                ip = ipr_norm(ip)

            # Standard address class for resolving addresses.
            dest = Address(ip, port, nic=self.nic, conf=conf)

        # Ensure address instances are resolved to IPs.
        if isinstance(dest, Address):
            if not dest.resolved:
                await dest.res(route=self.route)

            # Auto-select IP based on route af or chosen nic.
            if self.route:
                af_list = (self.route.af,)
            else:
                af_list = self.nic.supported()

            # Select compatible IP for route AF
            lookup = {IP4: "IP4", IP6: "IP6"}
            for af in af_list:
                # If its not none use it.
                if getattr(dest, lookup[af]):
                    return dest.select_ip(af)

        raise ValueError("No supported IPs for resolv dest")

    async def create_or_use_socket(self):
        """
        Creates a socket if none was passed in, bound to route.
        Adds socket to global aionetiface_fds set.
        Sets route.bind_port to the bound local port.
        """
        if self.sock is None:
            self.sock = await socket_factory(
                route=self.route,
                dest_addr=self.dest,
                sock_type=UDP if self.proto == RUDP else self.proto,
                conf=self.conf,
            )

            # Failed to get a socket.
            if self.sock is None:
                raise OSError("Socket allocation failed")

            # Record socket ownership state.
            aionetiface_fds.add(self.sock)
            self.owns_socket = True

        # Routes can specify binding on port 0.
        # Resolve the port that the route ended up on.
        self.route.bind_port = self.sock.getsockname()[1]

    async def tcp_client_connect_if_needed(self):
        """
        Connects TCP socket to remote dest if this is a TCP client.
        Sets non-blocking mode.
        """
        if self.proto == TCP and self.dest is not None:
            loop = await self.get_loop()
            self.sock.settimeout(0)
            self.sock.setblocking(0)
            # Bind/dest visibility on every TCP client connect helps when
            # punch sockets fail with WinError 10049 / 10042 (wrong-NIC
            # bind) or when the destination resolved to a surprising IP.
            try:
                local_tup = self.sock.getsockname()
            except OSError:
                local_tup = None
            log(fstr(
                "Pipe.connect: tcp local={0} dest={1} con_timeout={2}s",
                (local_tup, self.dest.tup, self.conf.get("con_timeout")),
            ))
            try:
                await asyncio.wait_for(
                    loop.sock_connect(self.sock, self.dest.tup),
                    self.conf["con_timeout"],
                )
            except asyncio.TimeoutError as exc:
                log(fstr(
                    "Pipe.connect: TCP connect timed out local={0} dest={1}",
                    (local_tup, self.dest.tup),
                ))
                raise OSError("TCP connect timed out") from exc

    async def setup_pipe_events(self, msg_cb=None, up_cb=None):
        """
        Sets up PipeEvents for the pipe.
        Configures UDP/TCP, RUDP ack handlers, SSL, subscriptions, callbacks.
        """
        if self.conf.get("sock_only"):
            return

        """
        PipeEvents implements the same methods as asyncio Protocol classes
        but it also allows for send/recv and a few other methods.
        So code can be written in different styles.
        """
        loop = await self.get_loop()
        self.pipe_events = PipeEvents(
            sock=self.sock, route=self.route, loop=loop, conf=self.conf
        )

        # Manually set some attributes in pipe events not in constructor.
        self.pipe_events.proto = self.proto
        if msg_cb:
            self.pipe_events.add_msg_cb(msg_cb)

        # UDP / RUDP setup
        if self.proto in (UDP, RUDP):
            # Create a new protocol-based datagram transport.
            """
            On Windows with ProactorEventLoop, asyncio's default UDP
            transport does not work reliably across Python versions.
            Use the polling fallback for all Python versions on Windows.
            """
            on_windows = sys.platform == "win32"

            if on_windows:
                if not hasattr(loop, "udp_poller"):
                    udp_poller = UdpPoller(loop)
                    loop.udp_poller = udp_poller

                transport = PolledDatagramTransport(loop, self.sock, self.pipe_events)
                loop.udp_poller.register(transport)
            else:
                # Use standard asyncio method for creating UDP transport.
                # Note: Use patched version of create_datagram_endpoint.
                if isinstance(
                    loop,
                    (
                        asyncio.SelectorEventLoop,
                        CustomEventLoop,
                    ),
                ):
                    transport, _ = await create_datagram_endpoint(
                        loop=loop,
                        protocol_factory=lambda: self.pipe_events,
                        sock=self.sock,
                    )
                else:
                    # Unknown event loop: Use the loops own version.
                    transport, _ = await loop.create_datagram_endpoint(
                        protocol_factory=lambda: self.pipe_events, sock=self.sock
                    )

            # Likely never triggered as exceptions are raised instead.
            if transport is None:
                raise OSError("Failed to create datagram endpoint")

            # Wait for the UDP transport to signal ready.
            # Use ensure_future so we can cancel the wait without cancelling
            # the underlying Event (which stays set for later callers), but
            # we DO cancel the waiting coroutine itself to free the task.
            fut = asyncio.ensure_future(self.pipe_events.stream_ready.wait())
            try:
                await asyncio.wait_for(asyncio.shield(fut), timeout=2)
            except asyncio.TimeoutError:
                fut.cancel()
                try:
                    await fut
                except asyncio.CancelledError:
                    pass

            # Record type of transport in pipe events.
            self.pipe_events.stream.set_handle(transport, client_tup=None)
            if self.dest is not None:
                self.pipe_events.set_endpoint_type(TYPE_UDP_CON)
            else:
                self.pipe_events.set_endpoint_type(TYPE_UDP_SERVER)

        # RUDP ack handlers
        if self.proto == RUDP:
            self.pipe_events.set_ack_handlers(
                is_ack=self.pipe_events.stream.is_ack,
                is_ackable=self.pipe_events.stream.is_ackable,
            )

        # TCP setup
        if self.proto == TCP:
            # Add new connection handler.
            if up_cb:
                self.pipe_events.add_up_cb(up_cb)

            if self.dest is None:
                # Start router for TCP messages.
                server = await create_tcp_server(
                    sock=self.sock,
                    pipe_events=self.pipe_events,
                    loop=loop,
                    conf=self.conf,
                )

                # Check transport started successfully.
                if server is None:
                    raise OSError("Failed to create TCP server")

                # Save transport returned from create server.
                self.pipe_events.set_tcp_server(server)

                # Saving the task is apparently needed
                # or the garbage collector could close it.
                if hasattr(server, "serve_forever"):
                    self.pipe_events.set_tcp_server_task(
                        asyncio.ensure_future(async_wrap_errors(server.serve_forever()))
                    )

                # Store type of endpoint in pipe events.
                self.pipe_events.set_endpoint_type(TYPE_TCP_SERVER)
            else:
                # TCP client
                if self.conf.get("use_ssl"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    server_hostname = ""
                    wrap_overhead = 5
                else:
                    ctx = None
                    server_hostname = None
                    wrap_overhead = 2

                # Wrap an already connected TCP socket.
                await loop.create_connection(
                    protocol_factory=lambda: self.pipe_events,
                    sock=self.sock,
                    ssl=ctx,
                    server_hostname=server_hostname,
                )

                # Wait for the TCP connection to signal ready.
                fut = asyncio.ensure_future(self.pipe_events.stream_ready.wait())
                try:
                    await asyncio.wait_for(asyncio.shield(fut), timeout=wrap_overhead)
                except asyncio.TimeoutError:
                    fut.cancel()
                    try:
                        await fut
                    except asyncio.CancelledError:
                        pass

                # Set the con handles.
                self.pipe_events.stream.set_handle(
                    self.pipe_events.transport, self.dest.tup
                )

                # Indicate endpoint is for a TCP con.
                self.pipe_events.set_endpoint_type(TYPE_TCP_CON)

        # Set dest and subscribe if no msg_cb
        if self.dest:
            self.pipe_events.stream.dest = self.dest
            self.pipe_events.stream.set_dest_tup(self.dest.tup)
            if not msg_cb:
                self.pipe_events.subscribe(SUB_ALL)

    def cleanup_on_error(self):
        """
        Closes socket if owned. Removes it from aionetiface_fds.
        Resets self.sock and self.owns_socket to prevent reuse.
        Idempotent.
        """
        if getattr(self, "_closed", False):
            return

        if self.owns_socket and self.sock:
            try:
                self.sock.close()
            except OSError:
                log_exception()
            if self.sock in aionetiface_fds:
                aionetiface_fds.discard(self.sock)

        # Clear state
        self.sock = None
        self.owns_socket = False
        self._closed = True


async def sock_to_pipe(sock, nic):
    """Wrap an already-connected socket in a Pipe by finding the matching route on nic."""
    # Useful variables from the socket.
    af = sock.family
    bind_tup = sock.getsockname()
    bind_ipr = IPR(bind_tup[0], af=af)
    bind_port = bind_tup[1]

    # Find a pre-existing route for this bind IP.
    # Comparisons use IPRange to normalise IPs.
    use_route = None
    for route in nic.rp[af]:
        if bind_ipr in route.nic_ips:
            use_route = route
            break
        if bind_ipr in route.link_locals:
            use_route = route
            break

    """
    If the associated route for the bind IP can't be found
    for the NIC then raise an exception. If the bind IP
    was set to loopback or all addresses -- set to new route.
    """
    if not use_route:
        not_nic_ips = VALID_LOOPBACKS + VALID_ANY_ADDR
        if bind_tup[0] in not_nic_ips:
            use_route = nic.route(af)
        else:
            raise LookupError("Cannot find associated route for NIC bind.")

    # Associate a particular route with a bound port.
    await use_route.bind(port=bind_port)

    # Setup the pipe at that route.
    pipe = await Pipe(
        sock.type,  # Transport protocol.
        # Allows messages to be routed back to the handle.
        # TODO: this is really a bad mechanism?
        sock.getpeername()[:2],  # Dest tup turned to Addr by resolving
        use_route,  # Route associated with a nic and bind details.
        sock=sock,  # The actual socket.
    ).connect()  # Won't connect when socket is passed.

    # Return pipe.
    return pipe
