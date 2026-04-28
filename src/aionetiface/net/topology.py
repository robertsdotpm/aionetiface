"""Network topology helpers (public vs private, loopback detection)."""
from typing import Any, List, Optional
from .net_defs import VALID_AFS, IP4, IP6
from .ip_range import IPRange
from ..nic.nat.nat_defs import (
    STUN_PORT, MAX_MAP_NO, USE_MAP_NO, OPEN_INTERNET, SYMMETRIC_UDP_FIREWALL,
    FULL_CONE, RESTRICT_NAT, RESTRICT_PORT_NAT, SYMMETRIC_NAT, BLOCKED_NAT,
    NA_DELTA, EQUAL_DELTA, PRESERV_DELTA, INDEPENDENT_DELTA, DEPENDENT_DELTA,
    RANDOM_DELTA, EASY_NATS, DELTA_N, PREDICTABLE_NATS, FUSSY_NATS, BLOCKING_NATS,
)
from ..nic.nat.nat_utils import (
    delta_info, nat_info, delta_test, nats_intersect, nats_can_predict,
    f_is_open, f_can_predict, f_is_hard, valid_mappings_len,
)
from ..utility.utils import (
    to_b,
    to_n,
    to_s,
    is_number,
    is_bytes,
    ensure_resolved,
    in_range,
    MAX_PORT,
    log,
    async_test,
)


def validate_node_addr(addr: Any) -> Optional[Any]:
    """Validate all per-AF interface fields in a parsed node address dict and return it, or None on failure."""
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


def parse_server_hints(buf: Any) -> List[Any]:
    """Decode a server-hint section into a list of {af, host, port} dicts.

    Wire shape: [af,host,port]|[af,host,port]|... or empty/b'0'.
    Used for the optional MQTT-broker-hint and TURN-server-hint
    sections in node addresses (positions 5 and 6 of the addr_bytes
    split on '^'). The hints let a peer advertise "I am reliably
    connected at these third-party servers right now"; remote
    callers prefer publishing/relaying via these before falling
    back to their own rendezvous-derived candidate set, which
    sidesteps the broker-set non-convergence class of bug.
    """
    if not buf or buf == b"0":
        return []
    out = []
    for entry in buf.split(b"|"):
        if len(entry) < 2:
            continue
        inner = entry[1:-1] if entry[:1] == b"[" and entry[-1:] == b"]" else entry
        parts = inner.split(b",")
        if len(parts) != 3:
            continue
        try:
            af = to_n(parts[0])
            host = to_s(parts[1])
            port = to_n(parts[2])
        except (ValueError, TypeError):
            continue
        if not host or not port:
            continue
        out.append({"af": af, "host": host, "port": port})
    return out


def parse_node_addr(addr: Any) -> Optional[Any]:
    """Decode a serialised node address byte string into a structured dict keyed by address family.

    The wire format has two valid shapes:
      4 parts (legacy): af0^af1^pub_key_hex^machine_id
      6 parts (with hints): af0^af1^pub_key_hex^machine_id^mqtt_brokers^turn_servers

    Older addrs without hint sections are accepted and produce
    empty mqtt_brokers / turn_servers lists in the parsed dict.
    """
    # Already passed.
    if isinstance(addr, dict):
        return addr

    addr = to_b(addr)
    af_parts = addr.split(b"^")
    if len(af_parts) not in (4, 6):
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
        "mqtt_brokers": parse_server_hints(af_parts[4]) if len(af_parts) == 6 else [],
        "turn_servers": parse_server_hints(af_parts[5]) if len(af_parts) == 6 else [],
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
                        raise TypeError("Invalid type.")
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
    """Return True if any external IP in addr_bytes matches a route in the local interface list."""
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


def encode_server_hints(hints: List[Any]) -> bytes:
    """Encode a list of {af, host, port} hint dicts into wire bytes.

    Output shape matches parse_server_hints: [af,host,port]|...
    Empty list / None -> b"0" sentinel (matching the AF-with-no-routes convention).
    """
    if not hints:
        return b"0"
    parts = []
    for h in hints:
        af = h.get("af")
        host = h.get("host")
        port = h.get("port")
        if af is None or not host or not port:
            continue
        parts.append(b"[%d,%b,%d]" % (int(af), to_b(host), int(port)))
    return b"|".join(parts) if parts else b"0"


def make_node_addr(
    pub_key_hex: Any,
    machine_id: Any,
    interface_list: List[Any],
    port: int,
    ip: Any = None,
    nat: Any = None,
    if_index: Any = None,
    mqtt_brokers: Optional[List[Any]] = None,
    turn_servers: Optional[List[Any]] = None,
) -> bytes:
    """
    Encode node address information into a compact byte string.

    Wire format (fields separated by '^'):
        [IP4 interfaces] ^ [IP6 interfaces] ^ pub_key_hex ^ machine_id
        [^ mqtt_brokers ^ turn_servers]

    The mqtt_brokers and turn_servers sections are optional and
    only emitted when at least one is non-empty. Each hint entry
    has shape [af,host,port], joined by '|' within a section.
    Empty hint sections are encoded as b'0'. Receivers that do not
    pass these args produce 4-part addrs which older parsers
    accept unchanged.

    Each interface entry has the shape:
        [netiface_index, if_index, ext_ip, nic_ip, port, nat_type, delta_type, delta_val]

    Multiple interface entries within an AF are joined by '|'.
    An AF with no routes is encoded as the single byte b'0'.
    """
    ensure_resolved(interface_list)

    # Public-API input validation: raise on bad addr inputs so callers
    # see a typed error instead of an AssertionError that python -O
    # would silently strip.
    if not isinstance(pub_key_hex, (str, bytes)):
        raise TypeError(
            "pub_key_hex must be str or bytes, got {0}".format(
                type(pub_key_hex).__name__,
            )
        )
    if not isinstance(machine_id, (str, bytes)):
        raise TypeError(
            "machine_id must be str or bytes, got {0}".format(
                type(machine_id).__name__,
            )
        )
    if not len(interface_list):
        raise ValueError("interface_list must contain at least one interface")
    if not port:
        raise ValueError("port must be a non-zero integer")

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

    # Optional hint sections. Append both only when at least one is
    # non-empty so 4-part legacy addrs round-trip identically when
    # callers don't pass the new args.
    if mqtt_brokers or turn_servers:
        bufs.append(encode_server_hints(mqtt_brokers or []))
        bufs.append(encode_server_hints(turn_servers or []))

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
