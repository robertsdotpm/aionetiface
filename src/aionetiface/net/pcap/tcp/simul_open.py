"""Simultaneous-open helpers + four-tuple matching.

The TcpState class in state.py already handles simul-open at the
segment-processing level (SYN_SENT + bare-SYN -> SYN_RECEIVED -> SYN+ACK).
This module is a tiny facade that the p2pd plugin layer uses to:

  1. Build a connection ID (the four-tuple) so we can route inbound
     segments to the right TcpState instance when multiple connections
     share one pcap handle.
  2. Detect "this incoming SYN matches the one we just sent" without
     having to peek into TcpState internals.

The XP simul-open bypass workflow:
    Both peers, after coordination on the signal channel:
      1. Open a TcpState for the predicted four-tuple.
      2. Call state.open_simul(remote_ip, remote_port).
      3. Drive recv() in a loop; for every inbound TCP segment that
         matches the four-tuple, call state.on_segment(seg, src_ip).
      4. When state.is_established() returns True, hand the TcpState
         to a Connection wrapper and let send / recv flow.

References:
  - RFC 9293 sec 3.5 -- simultaneous open semantics
  - /home/x/projects/p2pd/CLAUDE.md "Vista/XP reverse_connect bug" for
    the path this is fixing
"""


class FourTuple(object):
    """Identify a connection by (local_ip, local_port, remote_ip, remote_port).

    Hashable so a dict can map FourTuple -> TcpState.  We deliberately
    do NOT include protocol -- the pcap reader already filters to TCP.
    """

    __slots__ = ("local_ip", "local_port", "remote_ip", "remote_port")

    def __init__(self, local_ip, local_port, remote_ip, remote_port):
        self.local_ip = local_ip
        self.local_port = int(local_port)
        self.remote_ip = remote_ip
        self.remote_port = int(remote_port)

    def key(self):
        return (self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        return isinstance(other, FourTuple) and self.key() == other.key()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "FourTuple({0}:{1} <-> {2}:{3})".format(
            self.local_ip, self.local_port,
            self.remote_ip, self.remote_port)


def match_inbound(seg, src_ip, dst_ip, ft):
    """True iff a captured (seg, src_ip, dst_ip) belongs to the connection
    described by `ft` (FourTuple)."""
    if dst_ip != ft.local_ip:
        return False
    if src_ip != ft.remote_ip:
        return False
    if seg.dst_port != ft.local_port:
        return False
    if seg.src_port != ft.remote_port:
        return False
    return True


def is_bare_syn(seg):
    """True iff seg is a SYN-without-ACK -- the simul-open trigger."""
    from .segment import FLAG_SYN, FLAG_ACK
    return seg.has_flag(FLAG_SYN) and not seg.has_flag(FLAG_ACK)
