"""PipeShim: adapter that gives a userspace pcap Connection the Pipe surface.

Why
---
The legacy tcp_punch plugin returns an aionetiface ``Pipe`` (kernel-
socket-backed) from ``plugin.result``. Downstream code in warpgate
(``gate.Link``, the demo, plugin chain teardown) is written against
the Pipe duck-type: ``send(buf[, dest])``, ``recv(sub, timeout=)``,
``subscribe(sub)``, ``unsubscribe(sub)``, ``close()``, plus a handful
of inspect-able attributes (``proto``, ``client_tup``, ``on_close``,
``pipe_events.stream.subs`` etc.).

The v2 tcp_punch_pcap_v2 plugin produces a userspace ``Connection``
(``aionetiface.net.pcap.tcp.conn.Connection``) instead. Connection's
own external API is correct for its own users (the smoke-test
``pcap_responder.py`` drives it directly via ``conn.send`` /
``conn.recv``), but it is NOT Pipe-shaped: ``recv`` takes ``n`` not a
subscription pattern, there is no ``subscribe`` concept, ``close``
is async-only, ``proto`` is missing, etc.

Two reasonable adapter shapes were considered:

1. **Inherit from Pipe.** Rejected because ``Pipe.__init__`` expects
   a route/sock pair and would try to ``socket_factory`` /
   ``setup_pipe_events`` against them. We have neither -- the
   underlying transport is a pcap Backend frames stream. The wiring
   between Pipe and PipeEvents/PipeClient is also tight enough that
   replacing the transport while keeping the queueing/subscribe
   layer would require monkey-patching deep into the Pipe lifecycle.
   The base class earns its keep when there's a real socket; with
   a userspace Connection it just gets in the way.

2. **Duck-typed shim.** Chosen. PipeShim holds a Connection
   reference, exposes the Pipe surface, and internally runs a pump
   task that pulls bytes off Connection.recv and fans them out to
   per-subscription queues using the same shape as PipeClient.subs
   (``offset -> [pattern, asyncio.Queue, handler]``). The
   sub-matching logic is intentionally simplified: TCP punch flows
   are point-to-point, so there's exactly one peer client_tup;
   pattern filtering by message regex is preserved for
   compatibility with random_probe / direct_connect which use
   prefix-matched subscriptions.

Lifecycle
---------
The plugin wraps the WINNING Connection only:

    shim = PipeShim(conn, peer_client_tup, firewall_teardown=...)
    plugin.result.set_result(shim)

Loser Connections are closed directly by the engine; they are never
wrapped.

``close()`` first stops the pump, then closes the underlying
Connection (which runs the FIN dance and tears down its driver /
retx tasks), then invokes the firewall teardown callback (always,
even on exception, so iptables/pf rules don't leak).

Connection state -> on_close
----------------------------
PipeShim exposes ``on_close`` as an ``asyncio.Event`` matching the
Pipe.pipe_events.on_close shape. The pump task sets the event when
Connection.closed_event fires (state machine reached CLOSED), when
Connection's TcpState.aborted goes true (RST/abort), or when
``close()`` is called.

Python 3.5 / fstr / no leading underscores / no removed prints
all per project policy.
"""
import asyncio
import re

try:
    from ....utility.utils import fstr, log
except ImportError:
    def fstr(template, args):
        return template.format(*args)

    def log(msg):
        pass

from ...net_defs import SUB_ALL, TCP


def hash_sub(sub):
    """Match PipeClient.hash_sub semantics so callers that mix in a
    second client_tup match the same offset."""
    h = hash(sub[0]) if sub and sub[0] is not None else hash(None)
    if sub and len(sub) > 1 and sub[1] is not None:
        h += hash("{0}:{1}".format(sub[1][0], sub[1][1]))
    return h


class ShimStream(object):
    """Stand-in for pipe_events.stream.

    Downstream Link(managed=True) sets ``stream.subs = {}`` on the
    inbound shim, so we must expose a real dict. PipeClient.subs has
    the shape ``offset -> [sub_tuple, asyncio.Queue, handler]``; we
    use the same shape so the few code paths that introspect it
    behave normally.
    """

    def __init__(self):
        self.subs = {}
        # dest fields appear on real streams; left as None for shim.
        self.dest = None
        self.dest_tup = None


class ShimPipeEvents(object):
    """Stand-in for pipe.pipe_events.

    Exposes the small subset of PipeEvents downstream code reaches
    for: ``stream``, ``on_close``, ``proto``, ``is_running``,
    ``client_tup``. The shim's send/recv/subscribe live on PipeShim
    itself (matching Pipe's __getattr__ delegation: Pipe forwards to
    pipe_events). We could put them here and use __getattr__ on the
    shim, but a flat surface is easier to reason about.
    """

    def __init__(self, stream, on_close, proto, client_tup):
        self.stream = stream
        self.on_close = on_close
        self.proto = proto
        self.client_tup = client_tup
        self.is_running = True


class PipeShim(object):
    """Wrap a userspace pcap Connection in the Pipe duck-type surface.

    Parameters
    ----------
    connection : Connection
        The winning userspace Connection produced by the pcap punch
        engine. Must already be ESTABLISHED.
    client_tup : tuple
        Peer's (ip, port). Used for ``self.client_tup`` and as the
        client_tup field on enqueued messages so subscriptions with
        a client_tup pattern can match.
    firewall_teardown : callable or None
        Zero-arg synchronous callable invoked from close()'s finally
        block. Used to remove the iptables / pf DROP rule installed
        before the punch fired. None is fine for tests / paths that
        don't install firewall rules.
    chunk_size : int
        Max bytes per Connection.recv() pump cycle. 4096 matches
        Connection.recv's default and is friendly to the per-sub
        queue depth.
    loop : asyncio loop or None
    """

    def __init__(self, connection, client_tup=None,
                 firewall_teardown=None, chunk_size=4096, loop=None):
        self.connection = connection
        self.client_tup = client_tup
        self.firewall_teardown = firewall_teardown
        self.chunk_size = chunk_size
        self.loop = loop or asyncio.get_event_loop()

        # Pipe-surface attributes.
        self.proto = TCP
        self.sock = None  # No kernel socket on the pcap path.
        self.route = None
        self.nic = None
        self.dest = None
        self.on_close = asyncio.Event()
        self.is_running = True
        self.closed = False

        # Pipe-events stand-in (so Link.managed clearing of subs works).
        self.stream = ShimStream()
        self.pipe_events = ShimPipeEvents(
            self.stream, self.on_close, self.proto, self.client_tup,
        )

        # Receive pump task -- pulls from Connection.recv and routes
        # into the per-sub queues using PipeClient-style matching.
        self.pump_task = self.loop.create_task(self.pump_loop())

        # Watcher for Connection close -> on_close event.
        self.watcher_task = self.loop.create_task(self.close_watcher())

    # --- subscription management ---------------------------------------

    def subscribe(self, sub=None, handler=None):
        """Register a subscription. Matches PipeClient.subscribe shape."""
        if sub is None:
            sub = SUB_ALL
        offset = hash_sub(sub)
        if offset not in self.stream.subs:
            # asyncio.Queue with bounded size: matches the
            # NET_CONF["max_qsize"] default of 100 used in PipeClient.
            self.stream.subs[offset] = [sub, asyncio.Queue(100), handler]
        return offset

    def unsubscribe(self, sub):
        offset = hash_sub(sub)
        if offset in self.stream.subs:
            del self.stream.subs[offset]
        return self

    # --- send / recv (Pipe-shaped) -------------------------------------

    async def send(self, data, dest_tup=None):
        """Send bytes via the underlying Connection.

        dest_tup is accepted for Pipe-compatibility but ignored: a
        Connection is point-to-point and already pinned to one peer.
        """
        if self.closed or not self.is_running:
            return 0
        try:
            n = await self.connection.send(data)
        except Exception as exc:
            log(fstr("PipeShim.send: {0}", (exc,)))
            return 0
        # Pipe.send returns the result of stream.send which can be 0/1
        # (UDP) or the byte count for TCP transports. Return the byte
        # count from Connection.send for consistency.
        return n

    async def recv(self, sub=None, timeout=2, full=False):
        """Wait for a matching message on the subscription queue.

        Mirrors PipeClient.recv: timeout=None means use a long
        default (we keep 2 s, same as Pipe default); returns None on
        timeout or close; returns ``[client_tup, data]`` when
        ``full=True``.
        """
        if sub is None:
            sub = SUB_ALL
        recv_timeout = timeout if timeout is not None else 2
        offset = hash_sub(sub)
        # Auto-subscribe on first recv if the caller didn't subscribe
        # explicitly. Pipe doesn't do this (it requires a prior
        # subscribe), but the smoke-test responder + the demo both
        # often skip the subscribe step; matching that behaviour
        # here keeps the shim friendly.
        if offset not in self.stream.subs:
            self.subscribe(sub)
        try:
            entry = self.stream.subs[offset]
            q = entry[1]
            ret = await asyncio.wait_for(q.get(), recv_timeout)
        except (asyncio.TimeoutError, OSError, ConnectionError):
            return None
        # Close sentinel: [None, None] -- pump injects this on
        # Connection-closed so blocked recv() callers wake up.
        if ret[1] is None:
            return None
        if full:
            return ret
        return ret[1]

    async def recv_n(self, n, sub=None):
        """Accumulate at least n bytes across one or more recv calls."""
        if sub is None:
            sub = SUB_ALL
        buf = b""
        while len(buf) < n:
            out = await self.recv(sub)
            if out is None:
                break
            buf += out
        return buf

    # --- pump (Connection.recv -> per-sub queues) ----------------------

    async def pump_loop(self):
        """Pull bytes off Connection.recv, fan-out to matching subs.

        Mirrors PipeClient.add_msg routing: each subscription has a
        pattern + optional client_tup filter + optional handler. The
        pcap stack delivers bytes only -- no datagram boundaries --
        so each pump cycle's bytes become one "message" for
        subscriber-routing purposes. This matches how the legacy
        kernel TCP Pipe delivers TCP data (TCPClientProtocol's
        data_received calls add_msg with the chunk as-is).
        """
        try:
            while True:
                if self.closed:
                    return
                try:
                    data = await self.connection.recv(self.chunk_size,
                                                     timeout=None)
                except Exception as exc:
                    log(fstr("PipeShim.pump_loop recv error {0}", (exc,)))
                    break
                if not data:
                    # Connection closed.
                    break
                self.dispatch(data)
        finally:
            # Wake blocked recv callers.
            self.broadcast_close_sentinel()

    def dispatch(self, data):
        """Route data into every matching subscription's queue."""
        if not self.stream.subs:
            return
        client_tup = self.client_tup
        for sub, q, handler in list(self.stream.subs.values()):
            b_msg_p = sub[0] if sub else None
            sub_tup = sub[1] if sub and len(sub) > 1 else None
            # Client_tup filter (port=0 means "any port on this IP").
            if sub_tup is not None and client_tup is not None:
                if sub_tup[1]:
                    if sub_tup != client_tup:
                        continue
                else:
                    if sub_tup[0] != client_tup[0]:
                        continue
            # Pattern filter (b"" or None means SUB_ALL).
            if b_msg_p:
                try:
                    if not re.findall(b_msg_p, data):
                        continue
                except (TypeError, re.error):
                    continue
            if handler is not None:
                # Pipe's run_handler accepts (pipe_events, handler,
                # client_tup, data); we mimic the bare-handler form.
                try:
                    res = handler(client_tup, data)
                    if asyncio.iscoroutine(res):
                        self.loop.create_task(res)
                except Exception as exc:
                    log(fstr("PipeShim handler raised {0}", (exc,)))
                continue
            # Enqueue.
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait([client_tup, data])
            except asyncio.QueueFull:
                pass

    def broadcast_close_sentinel(self):
        """Wake every blocked recv() with the [None, None] sentinel."""
        for sub, q, handler in list(self.stream.subs.values()):
            try:
                q.put_nowait([None, None])
            except asyncio.QueueFull:
                # Drop the oldest entry and try once more so the
                # close sentinel actually lands; a recv() blocked on
                # a full queue is the case we most need to unblock.
                try:
                    q.get_nowait()
                    q.put_nowait([None, None])
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    # --- close lifecycle -----------------------------------------------

    async def close_watcher(self):
        """Set on_close once Connection signals it's done."""
        try:
            await self.connection.closed_event.wait()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log(fstr("PipeShim.close_watcher {0}", (exc,)))
        finally:
            self.on_close.set()
            self.is_running = False

    async def close(self, force=False, keep_clients=False):
        """Tear down the shim, the underlying Connection, and the
        firewall rule (always, even on exception)."""
        if self.closed:
            return
        self.closed = True
        self.is_running = False
        # Cancel pump first so it doesn't race against Connection.close
        # pulling the reader out from under it.
        pump = self.pump_task
        self.pump_task = None
        if pump is not None:
            pump.cancel()
            try:
                await pump
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log(fstr("PipeShim.close: pump await error {0}", (exc,)))
        # Close the underlying Connection. Connection.close()
        # internally handles its own driver / retx / reader teardown.
        try:
            await self.connection.close()
        except asyncio.CancelledError:
            # Closer was cancelled mid-await; surface that to caller.
            self.broadcast_close_sentinel()
            self.on_close.set()
            if self.firewall_teardown is not None:
                try:
                    self.firewall_teardown()
                except Exception as exc:
                    log(fstr("PipeShim.close: firewall teardown swallowed {0}",
                             (exc,)))
                self.firewall_teardown = None
            raise
        except Exception as exc:
            log(fstr("PipeShim.close: connection.close error {0}", (exc,)))
        # Drain watcher task.
        watcher = self.watcher_task
        self.watcher_task = None
        if watcher is not None and not watcher.done():
            watcher.cancel()
            try:
                await watcher
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        # Always wake blocked recv callers.
        self.broadcast_close_sentinel()
        self.on_close.set()
        # Always run firewall teardown LAST. Guarded so a teardown
        # exception doesn't mask earlier failure.
        if self.firewall_teardown is not None:
            try:
                self.firewall_teardown()
            except Exception as exc:
                log(fstr("PipeShim.close: firewall teardown swallowed {0}",
                         (exc,)))
            self.firewall_teardown = None

    # --- async context-manager sugar -----------------------------------

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
        return False
