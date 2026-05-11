"""Outbound pipe (TCP/UDP client) implementation."""
import asyncio
import re
from ...utility.utils import fstr, log, log_exception, run_handler
from ...protocol.ack_udp import ACKUDP
from ..net_defs import NET_CONF, SUB_ALL, UDP, RUDP, TCP, IP6
from .pipe_defs import TYPE_UDP_CON
from .pipe_utils import client_tup_norm, norm_client_tup


"""
The code in this class supports a pull / fetch style use-case.
More suitable for some apps whereas the parent class allows
for handles to handle messages as they come in. The fetching
API needs for messages to be subscribed to beforehand.
"""


class PipeClient(ACKUDP):
    """Pull-style client that queues incoming messages into per-subscription asyncio Queues."""

    def __init__(
        self, pipe_events, loop=None, conf=None
    ):
        super().__init__()
        self.conf = conf if conf is not None else NET_CONF
        self.dest = None
        self.dest_tup = None
        self.loop = loop

        # [Bool(msg)] = Queue.
        # Lets convert this to [b"msg pattern", b"host pattern"] = [Queue]
        self.subs = {}

        # Instance of the base proto class.
        self.pipe_events = pipe_events
        self.route = self.pipe_events.route

        # Used for doing send calls.
        self.handle = {}

    """
    (1) UDP is multiplexed and doesn't need a destination bound.
    (2) TCP cons have a dest set.
    (3) TCP and UDP servers won't have a dest.
    """

    def set_dest_tup(self, dest_tup):
        """Normalise and store the remote destination tuple for outbound sends."""
        dest_tup = client_tup_norm(dest_tup)
        self.dest_tup = dest_tup

    """
    Set internal handle used for doing sends.
    For UDP this is a asyncio.DatagramTransport.
    For TCP it's a asyncio.StreamWriter.
    """

    def set_handle(
        self, handle, client_tup=None
    ):
        """Store the transport handle, indexed by client_tup for TCP or as a single handle for UDP."""
        if client_tup is not None:
            client_tup = client_tup_norm(client_tup)
            self.handle[client_tup] = handle
        else:
            self.handle = handle

    def hash_sub(self, sub):
        """Compute a stable integer hash for a subscription tuple (msg_pattern, client_tup)."""
        h = hash(sub[0])
        if sub[1] is not None:
            client_tup_str = fstr(
                "{0}:{1}",
                (
                    sub[1][0],
                    sub[1][1],
                ),
            )
            h += hash(client_tup_str)

        return h

    # Subscribe to a certain message and host type.
    # sub = [b_msg_pattern, b_addr_pattern]
    # optional: 3rd field in sub = example match
    def subscribe(self, sub, handler=None):
        """Register a subscription for messages matching sub, optionally routing them to handler."""
        b_msg_p, client_tup = sub
        if client_tup is not None:
            if not isinstance(client_tup[1], int):
                raise TypeError(
                    "subscribe: client_tup[1] (port) must be int, got {0}".format(
                        type(client_tup[1]).__name__,
                    )
                )
            client_tup = norm_client_tup(client_tup)
            sub = (b_msg_p, client_tup)

        offset = self.hash_sub(sub)
        if offset not in self.subs:
            self.subs[offset] = [sub, asyncio.Queue(self.conf["max_qsize"]), handler]

        return offset

    # Remove a subscription.
    def unsubscribe(self, sub):
        """Remove the subscription matching sub and return self."""
        offset = self.hash_sub(sub)
        if offset in self.subs:
            del self.subs[offset]

        return self

    # Adds a message to the first valid bucket.
    """
    TODO: If the queue is full what should the default
    actions be? Should the program await the queue
    being empty? Should it discard data? Maybe on limit - 1
    call https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.remove_reader and on queue empty add it back.
    """

    def add_msg(self, data, client_tup):
        """Route an incoming message to any matching subscription queues or handlers."""
        # No subscriptions.
        if not len(self.subs):
            return

        # Norm compressed IPv6 addresses.
        client_tup = client_tup_norm(client_tup)

        # Add message to queue and raise an event.
        def do_add(q):
            """Enqueue data and client_tup into q, evicting the oldest item if the queue is full."""
            # Check queue isn't full.
            if q.full():
                # TODO: Remove sock from event select.
                # To give time for queue to be processed.
                q.get_nowait()

            # Put an item on the queue.
            assert isinstance(client_tup, tuple)
            q.put_nowait([client_tup, data])

        # Apply bool filters to message.
        msg_added = False
        for sub, q, handler in self.subs.values():
            # Msg pattern, address pattern.
            b_msg_p, m_client_tup = sub[:2]

            # Check client_addr matches their host pattern.
            if m_client_tup is not None:
                # Also check the source port.
                if not isinstance(m_client_tup[1], int):
                    raise TypeError(
                        "subscription pattern port must be int, got {0}".format(
                            type(m_client_tup[1]).__name__,
                        )
                    )
                if m_client_tup[1]:
                    if m_client_tup != client_tup:
                        continue

                # Ignore source port but check IPs.
                if not m_client_tup[1]:
                    if m_client_tup[0] != client_tup[0]:
                        continue

            # Check data matches their message pattern.
            if b_msg_p:
                msg_matches = re.findall(b_msg_p, data)
                if msg_matches == []:
                    continue

            # Execute message using handle instead of adding to queue.
            if handler is not None:
                run_handler(self.pipe_events, handler, client_tup, data)

                continue

            # Add message to queue.
            msg_added = True
            do_add(q)

        if not msg_added:
            log(
                fstr(
                    "Discarded {0} = {1}",
                    (
                        client_tup,
                        data,
                    ),
                )
            )

    # Async wait for a message that matches a pattern in a queue.
    async def recv(
        self, sub=None, timeout=2, full=False
    ):
        """Block until a message matching sub arrives, then return its data (or full tuple if full=True)."""
        if sub is None:
            sub = SUB_ALL
        recv_timeout = timeout or self.conf["recv_timeout"]
        msg_p, addr_p = sub
        if addr_p is not None:
            if not isinstance(addr_p[1], int):
                raise TypeError(
                    "recv: addr pattern port must be int, got {0}".format(
                        type(addr_p[1]).__name__,
                    )
                )
            addr_p = client_tup_norm(addr_p)
            sub = (msg_p, addr_p)

        offset = self.hash_sub(sub)
        try:
            # Sanity checking.
            if offset not in self.subs:
                raise LookupError("Sub not found. Forgot to subscribe.")

            # Get message from queue with timeout.
            _, q, handler = self.subs[offset]
            ret = await asyncio.wait_for(q.get(), recv_timeout)

            # [None, None] is the close sentinel injected by PipeEvents.close().
            if ret[1] is None:
                return None

            # Run handler if one is set.
            if handler is not None:
                run_handler(self.pipe_events, handler, ret[0], ret[1])

            # Return data, sender_tup.
            if full:
                return ret
            # Return only the data portion.
            return ret[1]
        except (OSError, ConnectionError, asyncio.TimeoutError):
            return None

    async def recv_n(self, n, sub=None):
        """Receive and concatenate messages until at least n bytes have been accumulated."""
        if sub is None:
            sub = SUB_ALL
        buf = b""
        while len(buf) < n:
            out = await self.recv(sub)
            if out is None:
                break
            buf += out

        return buf

    # Async send for TCP and UDP cons.
    # Listen servers also supported.
    async def send(self, data, dest_tup):
        """Send data to dest_tup over the underlying TCP or UDP transport and return 1 on success."""
        dest_tup = client_tup_norm(dest_tup)
        try:
            # Get handle reference.
            if isinstance(self.handle, dict):
                handle = self.handle[dest_tup]
            else:
                handle = self.handle

            # TCP send -- already bound to a target.
            # Indexed by writer streams per con.
            if isinstance(handle, asyncio.streams.StreamWriter):
                handle.write(data)
                await handle.drain()
                return 1

            # UDP send -- not connected - can be sent to anyone.
            # Single handle for multiplexing.
            if self.pipe_events.proto in (
                UDP,
                RUDP,
            ):
                # TYPE_UDP_CON means the Pipe was created with a non-None
                # dest (see pipe.py); it does NOT mean the OS socket was
                # connected via socket.connect().  These are multiplexed
                # (overloaded) UDP sockets that are never truly OS-connected.
                # Always pass dest_tup — passing None causes TypeError in the
                # asyncio transport because _address is None on unconnected
                # sockets.
                if self.pipe_events.endpoint_type == TYPE_UDP_CON:
                    handle.sendto(data, dest_tup)
                    return 1

                """
                When you bind to IPv6 you specify the 4 tup. The 4 tup must be
                provided for dest (ip, port, 0, scope_id) but the last two can be
                inferred. However, that depends on OS, event-loop type, and Python
                version. The correct pattern is to provide the full 4 tup for
                the dest tup as well.
                """
                if self.route.af == IP6:
                    if dest_tup[0][:2] in (
                        "fe",
                        "fd",
                    ):
                        nic_id = self.route.interface.nic_no or 0
                    else:
                        nic_id = 0

                    # 4 tup dest for UDP IPv6.
                    dest_tup = (dest_tup[0], dest_tup[1], 0, nic_id)

                handle.sendto(data, dest_tup)

                return 1

            # TCP send -- already bound to transport con.
            # TCP Transport instance.
            if self.pipe_events.proto == TCP:
                # This also works for SSL wrapped sockets.
                handle.write(data)

                # await self.pipe_events.safe_write(data)

                """
                await self.loop.sock_sendall(
                    self.pipe_events.sock,
                    data
                )
                """

                # await handle.drain()

                return 1

            return 0
        except (OSError, ConnectionError, ValueError):
            log(fstr(" send error {0}", (self.handle,)))
            log_exception()
            return 0
