from .net_defs import *
from .net_utils import *
from .ip_range import *
from ..nic.nat.nat_defs import *
from ..nic.nat.nat_utils import *
from ..settings import *

def validate_node_addr(addr):
    for af in VALID_AFS:
        for if_offset in addr[af]:
            if_info = addr[af][if_offset]

            # Is listen port right?
            if not in_range(if_info["port"], [1, MAX_PORT]):
                log("p2p addr: listen port invalid")
                return None
            
            # Check NAT type is valid.
            if not in_range(if_info["nat"]["type"], [OPEN_INTERNET, BLOCKED_NAT]):
                log("p2p addr: nat type invalid")
                return None

            # Check delta type is valid.
            if not in_range(if_info["nat"]["delta"]["type"], [NA_DELTA, RANDOM_DELTA]):
                log("p2p addr: delta type invalid")
                return None

            # Check delta value is valid.
            delta = if_info["nat"]["delta"]["value"]
            delta = -delta if delta < 0 else delta
            if not in_range(delta, [0, MAX_PORT]):
                log("p2p addr: Delta value invalid")
                return None
            
    return addr

def parse_node_addr(addr):
    # Already passed.
    if isinstance(addr, dict):
        return addr

    addr = to_b(addr)
    af_parts = addr.split(b'-')
    if len(af_parts) != 5:
        log("p2p addr invalid parts")
        return None

    # Parse signal server offsets.
    sig_part = af_parts.pop(0)
    if sig_part == b"None":
        signal = []
    else:
        p = sig_part.split(b";")
        signal = []
        for dest_buf in p:
            dest_parts = dest_buf.split(b",")
            if len(dest_parts) != 2:
                continue

            dest = (to_s(dest_parts[0]), int(dest_parts[1]))
            signal.append(dest)

    # Parsed dict.
    schema = [is_no, is_no, is_b, is_b, is_no,  is_no, is_no, is_no]
    translate = [to_n, to_n, to_b, to_b, to_n, to_n, to_n, to_n]
    out = {
        IP4: {},
        IP6: {},
        "node_id": to_s(af_parts[2]),
        "signal": signal,
        "machine_id": to_s(af_parts[3]),
        "vk": None,
        "bytes": addr,
    }

    for af_index, af_part in enumerate(af_parts[:2]):
        interface_infos = af_part.split(b'|')
        for info in interface_infos:
            # Strip outer braces.
            if len(info) < 2:
                continue
            inner = info[1:-1]

            # Split into components.
            parts = inner.split(b',')
            if len(parts) != 8:
                log("p2p addr: invalid parts no.")
                continue

            # Test type of field.
            # Convert to its end value if it passes.
            try:
                for j, part in enumerate(parts):
                    if not schema[j](part):
                        raise Exception("Invalid type.")
                    else:
                        parts[j] = translate[j](part)
            except Exception:
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[2]))
            except Exception:
                log("p2p addr: ip invalid.")
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[3]))
            except Exception:
                log("p2p addr: ip invalid.")
                continue
                    
            # Build dictionary of results.
            delta = delta_info(parts[6], parts[7])
            nat = nat_info(parts[5], delta)
            as_dict = {
                "netiface_index": parts[0],
                "if_index": parts[1],
                "ext": IPRange(to_s(parts[2])),
                "nic": IPRange(to_s(parts[3])),
                "nat": nat,
                "port": parts[4]
            }

            # Save results.
            af = VALID_AFS[af_index]
            out[af][parts[1]] = as_dict

    # Sanity check address.
    validate_node_addr(out)

    # Convert to tuple to prevent change.
    out["signal"] = tuple(out["signal"])

    return out

def node_addr_extract_exts(p2p_addr):
    exts = []
    for af in VALID_AFS:
        for info in p2p_addr[af]:
            exts.append(info["ext"])
            exts.append(info["nic"])

    return exts

def is_node_addr_us(addr_bytes, if_list):
    # Parse address bytes to address.
    addr = parse_node_addr(addr_bytes)

    # Check all address families.
    for af in VALID_AFS:
        # Check all interface details for AF.
        for info in addr[af]:
            # Compare the external address.
            ipr = info["ext"]

            # Set the right interface to check.
            if_index = info["if_index"]
            if if_index + 1 > len(if_list):
                continue

            # Check all routes in the interface.
            interface = if_list[if_index]
            for route in interface.rp[af].routes:
                # Only interested in the external address.
                for ext_ipr in route.ext_ips:
                    # IPs are equal or in same block.
                    if ipr in ext_ipr:
                        return True

    # Nothing found that matches.
    return False

"""
    Absolutely DERANGED. Or is it?

        can be up to N interfaces
[ IP4 nics
    [
        interface_offset,
        ext ip,
        nic ip,
        port,
        nat_type,
        delta_type,
        delta_val
    ]
    ,... more interfaces for AF family
],[IP6 nics ...],node_id
"""
def make_node_addr(node_id, machine_id, interface_list, sig_servers, port=NODE_PORT, ip=None, nat=None, if_index=None):
    ensure_resolved(interface_list)

    # Make the program crash early on invalid addr inputs.
    assert(isinstance(node_id, (str, bytes)))
    assert(isinstance(machine_id, (str, bytes)))
    assert(len(interface_list))
    assert(port)
    assert(isinstance(sig_servers, list))


    # Signal offsets to load.
    if len(sig_servers):
        sig_servers_buf = b""
        for dest in sig_servers:
            dest_buf = to_b(dest[0]) + b"," + to_b(str(dest[1])) + b";"
            sig_servers_buf += dest_buf

        bufs = [
            # Make signal pipe buf.
            sig_servers_buf
        ]
    else:
        # No signal offsets.
        bufs = [b"None"]

    for af in [IP4, IP6]:
        af_bufs = []
        for i, interface in enumerate(interface_list):
            # AF type is not supported.
            if not len(interface.rp[af].routes):
                continue

            r = interface.route(af)
            if r is None:
                continue

            if nat:
                nat_type = nat["type"]
                delta_type = nat["delta"]["type"]
                delta_value = nat["delta"]["value"]
            else:
                nat_type = interface.nat["type"]
                delta_type = interface.nat["delta"]["type"]
                delta_value = interface.nat["delta"]["value"]

            if af == IP4:
                int_ip = ip or to_b(r.nic())
            if af == IP6:
                int_ip = to_b(r.ext())
                if len(r.link_locals):
                    int_ip = to_b(str(r.link_locals[0]))
                if ip is not None:
                    int_ip = to_b(ip)

            af_bufs.append(b"[%d,%d,%b,%b,%d,%d,%d,%d]" % (
                interface.netiface_index,
                if_index or i,
                ip or to_b(r.ext()),
                int_ip,
                port,
                nat_type,
                delta_type,
                delta_value
            ))

        if len(af_bufs):
            af_bufs = b'|'.join(af_bufs)
        else:
            af_bufs = b''
        
        # The as_buf may be empty if AF has no routes.
        # Expected and okay.
        bufs.append(af_bufs or b"0")
    
    bufs.append(to_b(node_id))
    bufs.append(to_b(machine_id))
    return b'-'.join(bufs)

if __name__ == "__main__": # pragma: no cover
    from aionetiface.nic.interface import Interface
    async def test_p2p_addr():
        x = Interface("default")
        if_list = [x, x]
        node_id = b"noasdfosdfo"

        sig_servers = [("ovh1.p2pd.net", 8887), ("test.mosquitto.tld", 8887)]
        b_addr = make_node_addr(node_id, node_id, if_list, sig_servers)
        print(b_addr)

        addr = parse_node_addr(b_addr)
        print(addr)

    async_test(test_p2p_addr)
