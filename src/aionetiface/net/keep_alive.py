"""
Code taken from: https://github.com/sfinktah/keepalive/tree/master
- Made Linux platform case more flexible.
"""

import platform
import socket
from typing import Any, Optional

def set_keepalive_linux(
    sock: Any,
    after_idle_sec: Optional[int],
    interval_sec: Optional[int],
    max_fails: Optional[int],
) -> None:
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if after_idle_sec is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    if interval_sec is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    if max_fails is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def set_keepalive_osx(
    sock: Any,
    after_idle_sec: Optional[int],
    interval_sec: Optional[int],
    max_fails: Optional[int],
) -> None:
    """Set TCP keepalive on an open socket.

    sends a keepalive ping once every 3 seconds (interval_sec)
    """
    # scraped from /usr/include, not exported by python's socket module
    TCP_KEEPALIVE = 0x10
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if interval_sec is None:
        interval_sec = 3
    sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval_sec)


def set_keepalive_win(
    sock: Any,
    after_idle_sec: Optional[int],
    interval_sec: Optional[int],
    max_fails: Optional[int],
) -> None:
    """Configure TCP keepalive on an open socket using the Windows SIO_KEEPALIVE_VALS ioctl."""
    if after_idle_sec is not None and interval_sec is not None:
        sock.ioctl(
            socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec * 1000, interval_sec * 1000)
        )


def set_keep_alive(
    sock: Any, after_idle_sec: int = 60, interval_sec: int = 60, max_fails: int = 5
) -> None:
    """Apply platform-appropriate TCP keepalive settings to an open socket."""
    try:
        plat = platform.system()
        if plat == "Windows":
            return set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails)
        if plat == "Darwin":
            return set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails)
        # Should also work for BSD and Android.
        return set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    except OSError:
        pass
