"""Pure-Python userspace TCP -- populated in Phase 2.

Phase 1 only ships the OS pcap shims and the Backend abstraction.
The Phase-2 work will add:
    segment.py  -- TCP segment pack/unpack with checksum
    state.py    -- LISTEN / SYN-SENT / SYN-RECEIVED / ESTABLISHED FSM
    handshake.py -- three-way handshake + simul-open crossover path
    timers.py   -- retransmit / keepalive / MSL timers
"""
