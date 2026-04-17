"""
Write log messages to per-thread log files under ~/aionetiface/logs.

If that directory does not exist, all log calls are silently ignored.
"""

import os
import sys
import threading
import traceback
from .fstr import *
from ..install import get_aionetiface_install_root

LOGS_ROOT_PATH = os.path.join(
    get_aionetiface_install_root(),
    "logs"
)

log_fds = {}

def open_log_fd(tid):
    if tid not in log_fds:
        path = os.path.join(
            LOGS_ROOT_PATH,
            "aionetiface_" + str(os.getpid()) + "_" + str(tid) + ".log"
        )
        
        log_fds[tid] = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644
        )
        
    return log_fds[tid]

def log(msg):
    if not os.path.exists(LOGS_ROOT_PATH):
        return
    
    if type(msg) not in (str, bytes):
        return

    tid = threading.get_ident()
    fd = open_log_fd(tid)

    if type(msg) == bytes:
        os.write(fd, msg + b"\n")
    else:
        os.write(fd, msg.encode("utf-8") + b"\n")

def log_exception():
    exc = "".join(traceback.format_exception(*sys.exc_info()))
    log("EXCEPTION: " + exc.strip())

def log_p2p(msg, node_id):
    log(fstr("p2p <{0}>: {1}", (node_id, msg)))