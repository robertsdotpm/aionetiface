"""
Bridges an existing connected socket P to a new socket R (connected to destination).
Supports IPv4/IPv6 + TCP and UDP transports. Loops forever and ends if either side
disconnects (TCP) or stop_reader signals (UDP, since UDP has no graceful close).
"""

import selectors
import socket
from typing import Any, Dict, List, Tuple, Union
from ..utility.error_logger import log, log_exception
from .net_utils import sock_has_data


# Per-socket recv chunk size. For TCP this is the read window; for UDP
# it's the max datagram size we'll handle (65507 is the IPv4 UDP
# payload limit; rounding up keeps fragmented v6 jumbograms from
# truncating).
RECV_CHUNK = 65536


def close_pair(
    sock: Any, peers: Dict[Any, Any], selector: Any, buffers: Dict[Any, Any],
) -> None:
    """Cleans up both sides of the proxy connection."""
    peer = peers.pop(sock, None)
    if peer:
        peers.pop(peer, None)

    for s in (sock, peer):
        if not s:
            continue
        try:
            selector.unregister(s)
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass
        buffers.pop(s, None)


def _connect_reverse(
    destination: Tuple[str, int], sock_proto: int,
) -> Any:
    """Open the worker's reverse leg back to main. TCP -> create_connection,
    UDP -> bind a fresh socket and connect (UDP "connect" sets the kernel's
    default peer for send / filters recv to that peer).
    """
    if sock_proto == socket.SOCK_STREAM:
        return socket.create_connection(destination, timeout=10)

    # UDP path. Pick the right family from the destination IP literal.
    fam = socket.AF_INET6 if ":" in destination[0] else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect(destination)
    return s


def _read_chunk(sock: Any, sock_proto: int) -> bytes:
    """Read a chunk from sock. TCP: stream bytes (b"" == graceful close).
    UDP: one datagram (b"" is a real zero-length datagram, not a close).
    Raises BlockingIOError if no data available (selector mis-fired).
    """
    if sock_proto == socket.SOCK_STREAM:
        return sock.recv(RECV_CHUNK)
    # UDP: datagram boundary preserved. The socket is connect()ed so
    # recv() (no addr) returns datagrams from the connected peer only.
    return sock.recv(RECV_CHUNK)


def _enqueue(
    buffers: Dict[Any, Any], peer: Any, data: bytes, sock_proto: int,
) -> None:
    """Enqueue data for transmission to peer. TCP concatenates into a byte
    stream; UDP keeps each datagram as a separate list entry so boundaries
    are preserved across the bridge."""
    if sock_proto == socket.SOCK_STREAM:
        buffers[peer] = buffers.get(peer, b"") + data
        return
    buffers.setdefault(peer, [])
    buffers[peer].append(data)


def _has_pending(buf: Any, sock_proto: int) -> bool:
    """True if there's anything buffered for this socket to write."""
    if sock_proto == socket.SOCK_STREAM:
        return bool(buf)
    return bool(buf)  # list truthy iff non-empty


def _write_chunk(
    sock: Any, buffers: Dict[Any, Any], sock_proto: int,
) -> None:
    """Drain one chunk / one datagram from buffers[sock] to sock. Updates
    buffers[sock] in place."""
    if sock_proto == socket.SOCK_STREAM:
        buf = buffers.get(sock, b"")
        if not buf:
            return
        sent = sock.send(buf)
        buffers[sock] = buf[sent:]
        return
    queue = buffers.get(sock) or []
    if not queue:
        return
    # Pop the oldest datagram. send() is all-or-nothing on UDP -- a
    # short send() doesn't happen in practice on connected loopback,
    # but if it did, the leftover bytes are lost (UDP datagram is
    # atomic). Treat as "sent successfully" and move on.
    datagram = queue.pop(0)
    try:
        sock.send(datagram)
    except BlockingIOError:
        # Kernel buffer full; put it back at the head and let the
        # selector re-fire EVENT_WRITE.
        queue.insert(0, datagram)
    buffers[sock] = queue


def selector_proxy(
    socket_p: Any,
    destination: Tuple[str, int],
    stop_reader: Any,
    sock_proto: int = socket.SOCK_STREAM,
    socket_r: Any = None,
) -> None:
    """Bidirectionally proxy data between socket_p and a connection to destination.

    sock_proto selects the transport semantics for BOTH legs of the
    bridge -- socket.SOCK_STREAM (TCP, byte stream, recv/send) or
    socket.SOCK_DGRAM (UDP, datagram-preserving recv/send on UDP-
    connected sockets). socket_p is expected to already match this
    transport; for UDP it should already be UDP-connect()ed to the
    desired peer so the kernel filters recv to that peer and a bare
    send() targets it.

    socket_r=None means "open the reverse leg yourself" (TCP:
    create_connection; UDP: bind+connect). Passing a pre-built
    socket_r lets the caller create both endpoints up-front so the
    main loop knows the worker's bridge address before the worker
    sends anything -- needed for udp_punch where the connector side
    needs pipe.send to work before the first inbound datagram has
    set dest_tup.

    Stops when stop_reader has data, or (TCP only) when either side
    closes the connection.
    """
    selector = selectors.DefaultSelector()
    own_socket_r = socket_r is None
    try:
        if socket_r is None:
            socket_r = _connect_reverse(destination, sock_proto)

        socket_p.setblocking(False)
        socket_r.setblocking(False)

        peers = {socket_p: socket_r, socket_r: socket_p}
        # buffers[s] is bytes for TCP (concatenated stream) or
        # list-of-bytes for UDP (queue of pending datagrams). The
        # _enqueue / _write_chunk / _has_pending helpers normalise
        # the difference so the main loop body stays branchless.
        if sock_proto == socket.SOCK_STREAM:
            buffers = {socket_p: b"", socket_r: b""}  # type: Dict[Any, Any]
        else:
            buffers = {socket_p: [], socket_r: []}

        for s in peers:
            selector.register(s, selectors.EVENT_READ)

        while socket_p in peers:
            if sock_has_data(stop_reader):
                break

            events = selector.select(timeout=0.5)

            for key, mask in events:
                sock = key.fileobj
                if sock not in peers:
                    continue

                peer = peers[sock]

                # ---- READ LOGIC ----
                if mask & selectors.EVENT_READ:
                    try:
                        data = _read_chunk(sock, sock_proto)
                        if sock_proto == socket.SOCK_STREAM and not data:
                            # TCP graceful close on recv()->b"". UDP
                            # has no equivalent -- a zero-byte datagram
                            # is real data, not a close signal.
                            close_pair(sock, peers, selector, buffers)
                            if socket_p not in peers:
                                break
                            continue
                        _enqueue(buffers, peer, data, sock_proto)
                        # Tell selector we want EVENT_WRITE for the peer.
                        selector.modify(
                            peer,
                            selector.get_key(peer).events | selectors.EVENT_WRITE,
                        )
                    except BlockingIOError:
                        # Spurious selector wake; nothing to read.
                        pass
                    except (ConnectionResetError, OSError):
                        # UDP "connection reset" surfaces on Windows
                        # when an ICMP unreachable comes back from a
                        # previous send(). For TCP it's a real close.
                        if sock_proto == socket.SOCK_DGRAM:
                            continue
                        close_pair(sock, peers, selector, buffers)
                        if socket_p not in peers:
                            break
                        continue

                # ---- WRITE LOGIC ----
                if mask & selectors.EVENT_WRITE:
                    if not _has_pending(buffers.get(sock), sock_proto):
                        selector.modify(
                            sock,
                            selector.get_key(sock).events & ~selectors.EVENT_WRITE,
                        )
                        continue

                    try:
                        _write_chunk(sock, buffers, sock_proto)
                        if not _has_pending(buffers.get(sock), sock_proto):
                            selector.modify(
                                sock,
                                selector.get_key(sock).events & ~selectors.EVENT_WRITE,
                            )
                    except (BrokenPipeError, OSError):
                        close_pair(sock, peers, selector, buffers)
                        if socket_p not in peers:
                            break

    except (OSError, ConnectionError):
        log_exception()

    finally:
        # Final cleanup. Three exception classes can fire here, all of
        # them mean "this socket is no longer in the selector", all of
        # them must be swallowed:
        #   * KeyError -- selector.unregister() on a socket that was
        #     already removed by close_pair on a peer disconnect.
        #   * OSError -- generic kernel-level "selector entry is gone".
        #   * ValueError -- the socket has been closed already, so
        #     fileno() returns -1 and selectors.py's _fileobj_lookup
        #     raises before selector.unregister gets a chance.
        # Letting any of these propagate killed the punching worker
        # AFTER tcp_punch had successfully established the socket
        # pair, producing NO_ECHO failures that look identical to a
        # NAT-prediction miss.
        for s in [socket_p, socket_r]:
            if s:
                try:
                    selector.unregister(s)
                except (KeyError, OSError, ValueError):
                    pass
                try:
                    s.close()
                except OSError:
                    pass
        selector.close()

    log("Selector proxy ending.")
