"""
Bridges an existing connected socket P to a new socket R (connected to destination).
Supports IPv4 and IPv6 automatically. Loops forever and ends if either side
disconnects. Written entirely by AI but seems to work.
"""

import selectors
import socket
from ..utility.error_logger import *
from .net_utils import *

import socket
import selectors

def close_pair(sock, peers, selector, buffers):
    """Cleans up both sides of the proxy connection."""
    peer = peers.pop(sock, None)
    if peer:
        peers.pop(peer, None)

    for s in (sock, peer):
        if not s:
            continue
        try:
            selector.unregister(s)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
        buffers.pop(s, None)

def selector_proxy(socket_p, destination, stop_reader):
    selector = selectors.DefaultSelector()
    socket_r = None
    try:
        # Establish connection to the final destination
        socket_r = socket.create_connection(destination, timeout=10)
        
        # Set both to non-blocking for the selector
        socket_p.setblocking(False)
        socket_r.setblocking(False)

        # Map sockets to their counterparts and initialize buffers
        peers = {socket_p: socket_r, socket_r: socket_p}
        buffers = {socket_p: b"", socket_r: b""}

        for s in peers:
            selector.register(s, selectors.EVENT_READ)

        # ---- main loop ----
        # Loop specifically relies on the proxy socket's presence
        while socket_p in peers:
            if sock_has_data(stop_reader):
                break

            # Check for activity; wake every 0.5s to check stop_reader
            events = selector.select(timeout=0.5)

            for key, mask in events:
                sock = key.fileobj
                
                # Safety: if a previous event in this batch closed the pair, skip
                if sock not in peers:
                    continue
                
                peer = peers[sock]

                # ---- READ LOGIC ----
                if mask & selectors.EVENT_READ:
                    try:
                        data = sock.recv(4096)
                        if data:
                            # Queue data for the OTHER socket
                            buffers[peer] += data
                            # Tell selector we want to WRITE to the peer now
                            selector.modify(
                                peer,
                                selector.get_key(peer).events | selectors.EVENT_WRITE
                            )
                        else:
                            # Empty read means the socket closed gracefully
                            close_pair(sock, peers, selector, buffers)
                            if socket_p not in peers: break 
                    except (ConnectionResetError, OSError):
                        close_pair(sock, peers, selector, buffers)
                        if socket_p not in peers: break
                        continue

                # ---- WRITE LOGIC ----
                if mask & selectors.EVENT_WRITE:
                    buf = buffers.get(sock, b"")
                    if not buf:
                        # Nothing left to send, stop watching for WRITE events
                        selector.modify(
                            sock,
                            selector.get_key(sock).events & ~selectors.EVENT_WRITE
                        )
                        continue

                    try:
                        sent = sock.send(buf)
                        buffers[sock] = buf[sent:]
                        # If buffer is cleared, stop watching for WRITE
                        if not buffers[sock]:
                            selector.modify(
                                sock,
                                selector.get_key(sock).events & ~selectors.EVENT_WRITE
                            )
                    except (BrokenPipeError, OSError):
                        close_pair(sock, peers, selector, buffers)
                        if socket_p not in peers: break

    except Exception:
        log_exception()

    finally:
        # Final cleanup for the selector and any remaining sockets
        for s in [socket_p, socket_r]:
            if s:
                try:
                    # Double check if still registered before closing
                    selector.unregister(s)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
        selector.close()

    log("Selector proxy ending.")