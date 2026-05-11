"""
Utility functions for building, sending, and parsing STUN messages.

Supports RFC 3489 (used for NAT type detection) and RFC 5389/8489.
The main entry point is get_stun_reply, which sends a STUN binding request
and returns the parsed reply with address fields attached.
"""

import re
from ...utility.utils import async_test, fstr, log, to_h, valid_port
from ...errors import ErrorNoReply
from .stun_defs import RFC3489, STUNAddrTup, STUNAttrs, STUNMsg
from ...net.ip_range import IPRange
from ...net.net_patterns import send_recv_loop


def stun_proc_attrs(af, attr_code, attr_data, msg):
    """Decode a single STUN attribute and attach the resulting address tuple to msg as rtup or ctup."""
    # Set our remote IP and port.
    if not hasattr(msg, "rtup"):
        xor_addr_attrs = [STUNAttrs.XorMappedAddressX, STUNAttrs.XorMappedAddress]
        if attr_code in xor_addr_attrs:
            stun_addr_field = STUNAddrTup(
                af=af,
                txid=msg.txn_id,
                magic_cookie=msg.magic_cookie,
            ).unpack(attr_code, attr_data)
            msg.rtup = stun_addr_field.tup

        if attr_code == STUNAttrs.MappedAddress:
            stun_addr_field = STUNAddrTup(af=af).unpack(attr_code, attr_data)
            msg.rtup = stun_addr_field.tup

    # Set the additional IP and port for this server.
    if not hasattr(msg, "ctup"):
        if attr_code == STUNAttrs.ChangedAddress:
            stun_addr_field = STUNAddrTup(af=af).unpack(attr_code, attr_data)
            msg.ctup = stun_addr_field.tup


def stun_proto(buf, af):
    """Unpack a raw STUN buffer, process all its attributes, and return (STUNMsg, remaining_bytes)."""
    msg, buf = STUNMsg.unpack(buf)
    msg.af = af
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()
        stun_proc_attrs(af, attr_code, attr_data, msg)

    return msg, buf


# Handles making a STUN request to a server.
# Pipe also accepts route and its upgraded to a pipe.
async def get_stun_reply(
    mode,
    dest_addr,
    reply_addr,
    pipe,
    attrs=None,
):
    """
    The function uses subscriptions to the TXID so that even
    on unordered protocols like UDP the right reply is returned.
    The reply address forms part of that pattern which is an
    elegant way to validate responses from change requests
    which will otherwise timeout on incorrect addresses.
    """
    if attrs is None:
        attrs = []
    # Build the STUN message.
    msg = STUNMsg(mode=mode)
    for attr in attrs:
        attr_code, attr_data = attr
        msg.write_attr(attr_code, attr_data)
    # Subscribe to replies that match the req tran ID.
    sub = (re.escape(msg.txn_id), reply_addr)
    pipe.subscribe(sub)

    # Send the req and get a matching reply.
    send_buf = msg.pack()
    try:
        recv_buf = await send_recv_loop(dest_addr, pipe, send_buf, sub)
    finally:
        pipe.unsubscribe(sub)
    if recv_buf is None:
        raise ErrorNoReply("STUN recv loop got no reply.")

    # Return response.
    reply, _ = stun_proto(recv_buf, pipe.route.af)
    reply.pipe = pipe
    reply.stup = reply_addr
    return reply


async def stun_reply_to_ret_dic(reply):
    ret = {}
    if reply is None:
        return None

    if hasattr(reply, "ctup"):
        ret["cip"] = reply.ctup[0]
        ret["cport"] = reply.ctup[1]
    else:
        return None

    if hasattr(reply, "rtup"):
        ret["rip"] = reply.rtup[0]
        ret["rport"] = reply.rtup[1]
    else:
        return None

    if hasattr(reply, "stup"):
        ret["sip"] = reply.stup[0]
        ret["sport"] = reply.stup[1]
    else:
        return None

    if hasattr(reply, "pipe"):
        try:
            ltup = reply.pipe.sock.getsockname()[0:2]
            ret["lip"], ret["lport"] = ltup
        except OSError:
            # Socket was closed before we could read the local address.
            return None
    else:
        return None

    ret["resp"] = True
    return ret


def validate_stun_reply(reply, mode):
    """Return reply if it contains all required address attributes with public IPs and valid ports, otherwise None."""
    if reply is None:
        return None

    # Pipe needs to exist to check change addrs.
    if not hasattr(reply, "pipe"):
        return None

    # Reply addr is stup of the server.
    req_attrs = ["stup", "rtup"]
    extra_attrs = req_attrs[:]
    if mode == RFC3489:
        extra_attrs.append("ctup")

    # Check attrs exist in the reply.
    for req_attr in extra_attrs:
        if not hasattr(reply, req_attr):
            log(
                fstr(
                    "{0}: no attr {1}",
                    (
                        to_h(reply.txn_id),
                        req_attr,
                    ),
                )
            )
            return None

    # The follow tups should all have pub IPs.
    for req_attr in extra_attrs:
        tup_ip, tup_port = getattr(reply, req_attr)[:2]
        host_limit = 0
        ipr = IPRange(tup_ip, bitlen=host_limit)
        if ipr.is_private:
            log(
                fstr(
                    "{0} {1}: {2} priv",
                    (
                        req_attr,
                        to_h(reply.txn_id),
                        tup_ip,
                    ),
                )
            )
            return None
        if not valid_port(tup_port):
            log(
                fstr(
                    "{0} {1}: {2} bad",
                    (
                        req_attr,
                        to_h(reply.txn_id),
                        tup_port,
                    ),
                )
            )
            return None

    return reply


async def run_stun_utils():
    m = STUNMsg()
    m.encode()


if __name__ == "__main__":
    async_test(run_stun_utils)
