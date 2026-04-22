"""
Write log messages to per-thread log files under ~/aionetiface/logs.

If that directory does not exist, all log calls are silently ignored.
"""

import atexit
import os
import sys
import threading
import traceback
from typing import Any, Union
from .fstr import fstr

LOGS_ROOT_PATH = os.path.join(os.path.expanduser("~"), "aionetiface", "logs")

log_fds = {}


def _close_log_fds() -> None:
    """Close all open log file descriptors at interpreter shutdown."""
    for fd in list(log_fds.values()):
        try:
            os.close(fd)
        except OSError:
            pass
    log_fds.clear()


atexit.register(_close_log_fds)


def open_log_fd(tid: int) -> int:
    """Open (or reuse) the per-thread log file and return its OS-level file descriptor."""
    if tid not in log_fds:
        path = os.path.join(
            LOGS_ROOT_PATH, "aionetiface_" + str(os.getpid()) + "_" + str(tid) + ".log"
        )

        log_fds[tid] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)

    return log_fds[tid]


def log(msg: Union[str, bytes, Any]) -> None:
    """Write msg to the per-thread log file; silently no-ops if the logs directory is absent."""
    if not os.path.exists(LOGS_ROOT_PATH):
        return

    if type(msg) not in (str, bytes):
        return

    tid = threading.get_ident()
    fd = open_log_fd(tid)

    if isinstance(msg, bytes):
        os.write(fd, msg + b"\n")
    else:
        os.write(fd, msg.encode("utf-8") + b"\n")


def log_exception() -> None:
    """Log the current exception's traceback to the per-thread log file."""
    exc = "".join(traceback.format_exception(*sys.exc_info()))
    log("EXCEPTION: " + exc.strip())


def log_p2p(msg: Any, node_id: Any) -> None:
    """Log a p2p message prefixed with the node_id tag."""
    log(fstr("p2p <{0}>: {1}", (node_id, msg)))
