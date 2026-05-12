"""Network topology helpers (public vs private, loopback detection)."""
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


def validate_node_addr(addr):
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

            # Optional nic_subnet (CIDR prefix length), present when
            # the wire format carried the 9th field. 0 means "absent /
            # unknown" -- treat that as missing rather than enforcing
            # a specific bound. When set, it must fit the AF's bitlen.
            nic_subnet = getattr(if_info["nic"], "subnet", None)
            if nic_subnet is not None:
                max_bits = 32 if af == IP4 else 128
                if not in_range(nic_subnet, [0, max_bits]):
                    log("p2p addr: nic subnet out of range")
                    return None

            # Optional nic_port (10-field format). Must be a valid port when present.
            nic_port = if_info.get("nic_port")
            if nic_port is not None and nic_port != if_info["port"]:
                if not in_range(nic_port, [1, MAX_PORT]):
                    log("p2p addr: nic_port out of range")
                    return None

    return addr


def parse_server_hints(buf):
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


def parse_node_addr(addr):
    """Decode a serialised node address byte string into a structured dict keyed by address family.

    The wire format has these valid shapes:
      4 parts (legacy):       af0^af1^pub_key_hex^machine_id
      6 parts (with hints):   af0^af1^pub_key_hex^machine_id^mqtt_brokers^turn_servers
      7 parts (with peer-OS): af0^af1^pub_key_hex^machine_id^mqtt_brokers^turn_servers^os

    Older addrs without hint or OS sections are accepted and produce
    empty mqtt_brokers / turn_servers lists and os=None in the parsed
    dict. The OS token (when present) lets peers specialise behaviour
    -- tcp_punch uses it to pick a port range that matches the peer's
    NAT-classifier-validated ephemeral pool (Windows XP's narrow
    1025-5000 range is the canonical case).
    """
    # Already passed.
    if isinstance(addr, dict):
        return addr

    addr = to_b(addr)
    af_parts = addr.split(b"^")
    if len(af_parts) not in (4, 6, 7):
        log("p2p addr invalid parts")
        return None

    # Parsed dict.
    # Validators and converters per interface entry. The wire shape is
    # 8 fields (legacy) or 9 fields (with nic_subnet). The optional
    # 9th field is the CIDR prefix length of the directly-connected
    # network the nic_ip sits in (e.g. 64 for v6 SLAAC, 24 for /24
    # LANs). Receivers use it to gate same-LAN heuristics like
    # "should I attempt the link-local connect path" without having to
    # guess /64. Old 8-field addrs round-trip cleanly: nic IPRange's
    # .subnet stays None and downstream callers fall back to whatever
    # heuristic they used pre-subnet-on-the-wire.
    # Fields: netiface_index, if_index, ext_ip, nic_ip, port, nat_type, delta_type, delta_val [, nic_subnet]
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
        "mqtt_brokers": parse_server_hints(af_parts[4]) if len(af_parts) >= 6 else [],
        "turn_servers": parse_server_hints(af_parts[5]) if len(af_parts) >= 6 else [],
        # 7th part is the peer's OS token (e.g. "winxp", "linux") --
        # absent on legacy 4-part / 6-part addrs, which leaves os=None.
        # Downstream callers (notably tcp_punch's port allocator) treat
        # None as "use default behaviour".
        "os": to_s(af_parts[6]) if len(af_parts) >= 7 and af_parts[6] else None,
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
            if len(parts) not in (8, 9, 10):
                log("p2p addr: invalid parts no.")
                continue

            # Test type of field.
            # Convert to its end value if it passes. Schema/translate
            # cover the first 8 mandatory fields; the optional 9th
            # (nic_subnet) is validated separately below since it's
            # absent on legacy addrs.
            try:
                for j, part in enumerate(parts[:8]):
                    if not schema[j](part):
                        raise TypeError("Invalid type.")
                    else:
                        parts[j] = translate[j](part)
            except (ValueError, TypeError, IndexError):
                continue

            # Optional 9th field: nic_subnet (CIDR prefix length).
            # Drop the entry if present-but-malformed; pass-through
            # absent.
            nic_subnet = None
            if len(parts) >= 9:
                if not is_number(parts[8]):
                    continue
                try:
                    nic_subnet = to_n(parts[8])
                except (ValueError, TypeError):
                    continue
                parts[8] = nic_subnet

            # Optional 10th field: nic_port (port for NIC_BIND / link-local connects).
            # When absent, defaults to ext_port (the 5th field) for backward compat.
            nic_port = None
            if len(parts) == 10:
                if not is_number(parts[9]):
                    continue
                try:
                    nic_port = to_n(parts[9])
                except (ValueError, TypeError):
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

            # Build dictionary of results. nic.subnet is set when the
            # wire format carried it (9-field shape); otherwise stays
            # None and downstream code falls back to legacy heuristics.
            delta = delta_info(parts[6], parts[7])
            nat = nat_info(parts[5], delta)
            nic_ipr = IPRange(to_s(parts[3]))
            if nic_subnet is not None:
                nic_ipr.subnet = nic_subnet
            as_dict = {
                "netiface_index": parts[0],
                "if_index": parts[1],
                "ext": IPRange(to_s(parts[2])),
                "nic": nic_ipr,
                "nat": nat,
                "port": parts[4],
                "ext_port": parts[4],
                "nic_port": nic_port if nic_port is not None else parts[4],
            }

            # Save results.
            af = VALID_AFS[af_index]
            out[af][parts[1]] = as_dict

    # Sanity check address.
    validate_node_addr(out)

    return out


def node_addr_extract_exts(p2p_addr):
    """Return a flat list of all external and NIC IPRange objects in a p2p address."""
    exts = []
    for af in VALID_AFS:
        for info in p2p_addr[af].values():
            exts.append(info["ext"])
            exts.append(info["nic"])
    return exts


def is_node_addr_us(addr_bytes, if_list):
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


def encode_server_hints(hints):
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
    pub_key_hex,
    machine_id,
    interface_list,
    port,
    ip=None,
    nat=None,
    if_index=None,
    mqtt_brokers=None,
    turn_servers=None,
    if_ports=None,
    os=None,
):
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
        [netiface_index, if_index, ext_ip, nic_ip, port, nat_type, delta_type, delta_val, nic_subnet, nic_port]

    nic_subnet is the CIDR prefix length of the directly-connected network.
    nic_port is the port for NIC_BIND / link-local connects; when absent on
    receive it defaults to the ext_port (5th field) for backward compat.

    if_ports is an optional dict mapping (af, if_index_int) to
    {"ext": ext_port, "nic": nic_port}. When provided, per-NIC per-AF
    ports override the global port argument (useful when --port 0 causes
    v4 and v6 listeners to land on different OS-assigned ports).

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
    if not port and if_ports is None:
        raise ValueError("port must be a non-zero integer when if_ports is not provided")

    bufs = []
    for af in [IP4, IP6]:
        af_bufs = []
        for i, interface in enumerate(interface_list):
            # Resolve NAT fields (needed for both the normal and link-local path).
            # interface.nat is None until load_nat writes a result; treat that
            # the same as the worst-case unknown shape so peers can still
            # parse the announcement. Callers that care will validate later.
            if nat:
                source = nat
            elif interface.nat is not None:
                source = interface.nat
            else:
                source = nat_info()
            nat_type = source["type"]
            delta_type = source["delta"]["type"]
            delta_value = source["delta"]["value"]

            # Normal path: global routes exist for this AF.
            if len(interface.rp[af].routes) and af in interface.supported():
                r = interface.route(af)
                if r is None:
                    continue

                # Track the source IPRange for the nic slot so we can
                # ship its .subnet (CIDR prefix length) over the wire.
                # Receivers gate same-LAN heuristics on it -- having it
                # explicit avoids assuming /64 (v6 SLAAC) or /24 (v4)
                # when the actual network is wider/narrower.
                int_ipr = None
                if af == IP4:
                    int_ipr = r.nic_ips[0] if r.nic_ips else None
                    int_ip = ip or to_b(r.nic())
                if af == IP6:
                    int_ipr = r.ext_ips[0] if r.ext_ips else None
                    int_ip = to_b(r.ext())
                    if len(r.link_locals):
                        int_ipr = r.link_locals[0]
                        int_ip = to_b(str(r.link_locals[0]))
                    if ip is not None:
                        # User-supplied override; we don't know its
                        # subnet without another lookup, leave as 0.
                        int_ipr = None
                        int_ip = to_b(ip)

                nic_subnet = 0
                if int_ipr is not None and int_ipr.subnet is not None:
                    nic_subnet = int_ipr.subnet

                eff_if_index = if_index or i
                ports = (if_ports or {}).get((af, eff_if_index), {})
                eff_ext_port = ports.get("ext", port)
                eff_nic_port = ports.get("nic", port)
                af_bufs.append(
                    b"[%d,%d,%b,%b,%d,%d,%d,%d,%d,%d]"
                    % (
                        interface.netiface_index,
                        eff_if_index,
                        ip or to_b(r.ext()),
                        int_ip,
                        eff_ext_port,
                        nat_type,
                        delta_type,
                        delta_value,
                        nic_subnet,
                        eff_nic_port,
                    )
                )
                continue

            # Local-only fallback: no global routes but a local address exists.
            # For IPv6 this is a link-local (fe80::); for IPv4 it is a private
            # LAN IP stored here when STUN could not resolve a WAN address.
            # Encode the local address as both ext and nic so peers on the
            # same link/LAN can still reach this node.
            if interface.rp[af].link_locals:
                ll_ipr = interface.rp[af].link_locals[0]
                local_b = to_b(str(ll_ipr))
                nic_subnet = ll_ipr.subnet if ll_ipr.subnet is not None else 0
                eff_if_index = if_index or i
                ports = (if_ports or {}).get((af, eff_if_index), {})
                eff_ext_port = ports.get("ext", port)
                eff_nic_port = ports.get("nic", port)
                af_bufs.append(
                    b"[%d,%d,%b,%b,%d,%d,%d,%d,%d,%d]"
                    % (
                        interface.netiface_index,
                        eff_if_index,
                        local_b,
                        local_b,
                        eff_ext_port,
                        nat_type,
                        delta_type,
                        delta_value,
                        nic_subnet,
                        eff_nic_port,
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
    # callers don't pass the new args. The OS token (slot 7) is only
    # appended when explicitly requested AND the hint sections are
    # already present, to preserve positional decoding -- old peers
    # see 4 or 6 parts as before; new peers see 7 when OS is shipped.
    if mqtt_brokers or turn_servers or os:
        bufs.append(encode_server_hints(mqtt_brokers or []))
        bufs.append(encode_server_hints(turn_servers or []))
    if os:
        bufs.append(to_b(os))

    return b"^".join(bufs)


if __name__ == "__main__":  # pragma: no cover

    async def test_p2p_addr():
        """
        x = Interface("default")
        if_list = [x, x]
        node_id = b"noasdfosdfo"

        b_addr = make_node_addr(node_id, node_id, if_list, port=3000)
        print(b_addr)
        """

        b_addr = b"[1,0,192.0.2.1,198.51.100.1,3000,3,2,0]^0^00000000000000000000000000^0000000000000000000000000000000000000000000000000000000000000000"

        addr = parse_node_addr(b_addr)

    async_test(test_p2p_addr)
