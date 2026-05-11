"""Pure-Python userspace TCP.

No ctypes / no I/O at this layer; the conn.py module wires the FSM into
a pcap Backend.

Modules:
    segment.py     -- RFC 9293 TCP segment pack/parse + checksum
    state.py       -- TCP state machine (LISTEN, SYN_SENT, SYN_RECEIVED,
                      ESTABLISHED, FIN_WAIT_*, etc.) with the simul-open
                      branch from SYN_SENT
    simul_open.py  -- FourTuple matching + helpers
    timers.py      -- RFC 6298 retransmit + 2*MSL TIME-WAIT timer
    congestion.py  -- Minimum cwnd controller
    conn.py        -- Pipe-compatible Connection facade
"""
from . import segment, state, simul_open, timers, congestion, conn

__all__ = ("segment", "state", "simul_open", "timers", "congestion", "conn")
