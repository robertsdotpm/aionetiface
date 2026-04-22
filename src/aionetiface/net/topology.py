from typing import Any, List, Optional
from .net_defs import *
from .net_utils import *
from .ip_range import *
from ..nic.nat.nat_defs import *
from ..nic.nat.nat_utils import *
from ..settings import *
from ..utility.utils import to_b, to_n, is_number, is_bytes, ensure_resolved


def validate_node_addr(addr: Any) -> Optional[Any]:
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


def parse_node_addr(addr: Any) -> Optional[Any]:
    # Already passed.
    if isinstance(addr, dict):
        return addr

    addr = to_b(addr)
    af_parts = addr.split(b"^")
    if len(af_parts) != 4:
        log("p2p addr invalid parts")
        return None

    # Parsed dict.
    # Validators and converters for each of the 8 fields per interface entry.
    # Fields: netiface_index, if_index, ext_ip, nic_ip, port, nat_type, delta_type, delta_val
    schema = [
        is_number,
        is_number,
        is_bytes,
        is_bytes,
        is_number,
        is_number,
        is_number,
        is_number,
    ]
    translate = [to_n, to_n, to_b, to_b, to_n, to_n, to_n, to_n]
    out = {
        IP4: {},
        IP6: {},
        "pub_key_hex": to_s(af_parts[2]),
        "machine_id": to_s(af_parts[3]),
        "vk": None,
        "bytes": addr,
    }

    for af_index, af_part in enumerate(af_parts[:2]):
        interface_infos = af_part.split(b"|")
        for info in interface_infos:
            # Strip outer braces.
            if len(info) < 2:
                continue
            inner = info[1:-1]

            # Split into components.
            parts = inner.split(b",")
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
            except (ValueError, TypeError, IndexError):
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[2]))
            except ValueError:
                log("p2p addr: ip invalid.")
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[3]))
            except ValueError:
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
                "port": parts[4],
            }

            # Save results.
            af = VALID_AFS[af_index]
            out[af][parts[1]] = as_dict

    # Sanity check address.
    validate_node_addr(out)

    return out


def node_addr_extract_exts(p2p_addr: Any) -> List[Any]:
    """Return a flat list of all external and NIC IPRange objects in a p2p address."""
    exts = []
    for af in VALID_AFS:
        for info in p2p_addr[af].values():
            exts.append(info["ext"])
            exts.append(info["nic"])
    return exts


def is_node_addr_us(addr_bytes: Any, if_list: List[Any]) -> bool:
    # Parse address bytes to address.
    addr = parse_node_addr(addr_bytes)

    # Check all address families.
    for af in VALID_AFS:
        # Check all interface details for AF.
        for info in addr[af].values():
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


def make_node_addr(
    pub_key_hex: Any,
    machine_id: Any,
    interface_list: List[Any],
    port: int,
    ip: Any = None,
    nat: Any = None,
    if_index: Any = None,
) -> bytes:
    """
    Encode node address information into a compact byte string.

    Wire format (fields separated by '^'):
        [IP4 interfaces] ^ [IP6 interfaces] ^ pub_key_hex ^ machine_id

    Each interface entry has the shape:
        [netiface_index, if_index, ext_ip, nic_ip, port, nat_type, delta_type, delta_val]

    Multiple interface entries within an AF are joined by '|'.
    An AF with no routes is encoded as the single byte b'0'.
    """
    ensure_resolved(interface_list)

    # Make the program crash early on invalid addr inputs.
    assert isinstance(pub_key_hex, (str, bytes))
    assert isinstance(machine_id, (str, bytes))
    assert len(interface_list)
    assert port

    bufs = []
    for af in [IP4, IP6]:
        af_bufs = []
        for i, interface in enumerate(interface_list):
            # Resolve NAT fields (needed for both the normal and link-local path).
            if nat:
                nat_type = nat["type"]
                delta_type = nat["delta"]["type"]
                delta_value = nat["delta"]["value"]
            else:
                nat_type = interface.nat["type"]
                delta_type = interface.nat["delta"]["type"]
                delta_value = interface.nat["delta"]["value"]

            # Normal path: global routes exist for this AF.
            if len(interface.rp[af].routes):
                r = interface.route(af)
                if r is None:
                    continue

                if af == IP4:
                    int_ip = ip or to_b(r.nic())
                if af == IP6:
                    int_ip = to_b(r.ext())
                    if len(r.link_locals):
                        int_ip = to_b(str(r.link_locals[0]))
                    if ip is not None:
                        int_ip = to_b(ip)

                af_bufs.append(
                    b"[%d,%d,%b,%b,%d,%d,%d,%d]"
                    % (
                        interface.netiface_index,
                        if_index or i,
                        ip or to_b(r.ext()),
                        int_ip,
                        port,
                        nat_type,
                        delta_type,
                        delta_value,
                    )
                )
                continue

            # Local-only fallback: no global routes but a local address exists.
            # For IPv6 this is a link-local (fe80::); for IPv4 it is a private
            # LAN IP stored here when STUN could not resolve a WAN address.
            # Encode the local address as both ext and nic so peers on the
            # same link/LAN can still reach this node.
            if interface.rp[af].link_locals:
                local_b = to_b(str(interface.rp[af].link_locals[0]))
                af_bufs.append(
                    b"[%d,%d,%b,%b,%d,%d,%d,%d]"
                    % (
                        interface.netiface_index,
                        if_index or i,
                        local_b,
                        local_b,
                        port,
                        nat_type,
                        delta_type,
                        delta_value,
                    )
                )

        if len(af_bufs):
            af_bufs = b"|".join(af_bufs)
        else:
            af_bufs = b""

        # The as_buf may be empty if AF has no routes.
        # Expected and okay.
        bufs.append(af_bufs or b"0")

    bufs.append(to_b(pub_key_hex))
    bufs.append(to_b(machine_id))
    return b"^".join(bufs)


if __name__ == "__main__":  # pragma: no cover

    async def test_p2p_addr() -> None:
        """
        x = Interface("default")
        if_list = [x, x]
        node_id = b"noasdfosdfo"

        b_addr = make_node_addr(node_id, node_id, if_list, port=3000)
        print(b_addr)
        """

        b_addr = b"[1,0,113.29.240.148,10.0.1.230,3000,3,2,0]^0^e430b89759a5d75f9ec80798a^7a64285df710807300863496142f032a5b2365ce6a4a11f9b400fc1e6b4326e5"

        addr = parse_node_addr(b_addr)
        print(addr)

    async_test(test_p2p_addr)
