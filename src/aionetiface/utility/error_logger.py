"""
Write log messages to per-thread log files under ~/aionetiface/logs.

If that directory does not exist, all log calls are silently ignored.
"""

import atexit
import os
import re
import sys
import threading
import traceback
from typing import Any, Union
from .fstr import fstr

LOGS_ROOT_PATH = os.path.join(os.path.expanduser("~"), "aionetiface", "logs")

# Optional human-readable tag for log filenames -- e.g. the test runner
# sets AIONETIFACE_LOG_TAG=test_auto_connect_reverse before invoking
# python -m unittest. The tag is sanitised to a safe filename slug and
# prepended to the log filename, so logs become greppable by test name
# instead of being identifiable only by the opaque (pid, tid) pair.
LOG_TAG_ENV = "AIONETIFACE_LOG_TAG"
LOG_TAG_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def log_tag_slug() -> str:
    """Return the sanitised value of AIONETIFACE_LOG_TAG, or '' if unset."""
    raw = os.environ.get(LOG_TAG_ENV, "")
    if not raw:
        return ""
    slug = LOG_TAG_SLUG_RE.sub("_", raw).strip("_")
    return slug[:80]  # cap so we don't blow past path-length limits on Windows


log_fds = {}


def close_log_fds() -> None:
    """Close all open log file descriptors at interpreter shutdown."""
    for fd in list(log_fds.values()):
        try:
            os.close(fd)
        except OSError:
            pass
    log_fds.clear()


atexit.register(close_log_fds)


def open_log_fd(tid: int) -> int:
    """Open (or reuse) the per-thread log file and return its OS-level file descriptor."""
    if tid not in log_fds:
        tag = log_tag_slug()
        if tag:
            name = "aionetiface_" + tag + "_" + str(os.getpid()) + "_" + str(tid) + ".log"
        else:
            name = "aionetiface_" + str(os.getpid()) + "_" + str(tid) + ".log"
        path = os.path.join(LOGS_ROOT_PATH, name)

        log_fds[tid] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)

    return log_fds[tid]


def log(msg: Union[str, bytes, Any]) -> None:
    """Write msg to the per-thread log file; silently no-ops if the logs directory is absent."""
    if not os.path.exists(LOGS_ROOT_PATH):
        return

    if not isinstance(msg, (str, bytes)):
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
