"""Pipe-flavoured convenience wrappers over the raw Backend.

The Backend ABC in backend.py exposes the minimum primitive set
(open / send / recv / set_filter).  Most callers do not want to write
their own asyncio-friendly loop on top of that, so this module ships
a small helper that:

- runs the synchronous recv() call in an executor thread so an
  asyncio task can `await` frame arrivals without blocking the loop;
- buffers received frames in a bounded asyncio.Queue so the consumer
  side can apply back-pressure;
- transparently delegates send/set_filter/close.

The Phase-3 userspace TCP plugin will wrap this in turn -- but the
Pipe-style API is generic enough that other future callers (raw
ICMP probes, custom DNS, etc.) can reuse it.

This module deliberately stays small in Phase 1.  Once the userspace
TCP layer is implemented we add `PcapTCPListener` / `PcapTCPConnector`
that integrate with aionetiface's existing Pipe layer (see
`net/pipe/` for the contract).
"""
import asyncio
import threading

try:
    # Available on the aionetiface install -- preferred for logging.
    from ...utility.fstr import fstr
except ImportError:
    def fstr(template, args):
        return template.format(*args)


class PcapReader(object):
    """Async wrapper around a Backend's blocking recv().

    Spins one daemon thread that calls Backend.recv() in a loop and
    pushes the bytes onto an asyncio.Queue (bridged via
    loop.call_soon_threadsafe so the queue is owned by the loop's
    thread, not the reader's).

    Usage:
        backend = factory.open("lo")
        reader = PcapReader(backend, loop=asyncio.get_event_loop())
        reader.start()
        try:
            frame = await reader.next_frame(timeout=1.0)
            ...
        finally:
            reader.stop()
            backend.close()
    """

    def __init__(self, backend, loop=None, queue_max=512, poll_ms=100):
        self.backend = backend
        self.loop = loop or asyncio.get_event_loop()
        self.queue = asyncio.Queue(maxsize=queue_max)
        self.poll_ms = poll_ms
        self.stop_flag = threading.Event()
        self.thread = None

    def start(self):
        if self.thread is not None:
            return
        self.thread = threading.Thread(
            target=self.run_loop, name="pcap-reader", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_flag.set()
        # Don't join with hold-lock: the reader thread is a daemon and
        # the recv() call returns within poll_ms anyway.
        self.thread = None

    def run_loop(self):
        while not self.stop_flag.is_set():
            try:
                frame = self.backend.recv(timeout_ms=self.poll_ms)
            except Exception as exc:
                # Surface the failure once and exit; further frames are
                # impossible on a broken handle.
                self.loop.call_soon_threadsafe(self.queue.put_nowait, None)
                return
            if frame is None:
                continue
            try:
                self.loop.call_soon_threadsafe(self.queue.put_nowait, frame)
            except asyncio.QueueFull:
                # Drop on the floor -- the consumer is slower than the
                # link.  Better than blocking the reader thread.
                continue

    async def next_frame(self, timeout=None):
        """Await the next frame (bytes), or None on sentinel / EOF.
        Raises asyncio.TimeoutError when timeout elapses with nothing
        in the queue."""
        if timeout is None:
            return await self.queue.get()
        return await asyncio.wait_for(self.queue.get(), timeout=timeout)


def open_async_reader(iface_name, bpf_filter="", snaplen=65535,
                      promisc=False, timeout_ms=10, loop=None):
    """One-shot helper: pick the current platform backend, open
    iface_name, apply the filter, and return (backend, PcapReader).

    The caller is responsible for `reader.stop()` and `backend.close()`
    when done -- usually paired in an asyncSetUp / asyncTearDown.
    """
    from .backend import get_backend
    factory = get_backend()
    backend = factory.open(
        iface_name, snaplen=snaplen, promisc=promisc, timeout_ms=timeout_ms)
    if bpf_filter:
        backend.set_filter(bpf_filter)
    reader = PcapReader(backend, loop=loop)
    reader.start()
    return backend, reader
