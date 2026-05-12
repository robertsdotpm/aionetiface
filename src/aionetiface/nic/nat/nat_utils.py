"""Helper functions for NAT type classification."""
import asyncio
import random
from .nat_defs import (
    STUN_PORT,
    MAX_MAP_NO,
    OPEN_INTERNET,
    SYMMETRIC_UDP_FIREWALL,
    RESTRICT_PORT_NAT,
    SYMMETRIC_NAT,
    EQUAL_DELTA,
    PRESERV_DELTA,
    INDEPENDENT_DELTA,
    DEPENDENT_DELTA,
    RANDOM_DELTA,
    EASY_NATS,
    PREDICTABLE_NATS,
)
from ...utility.utils import (
    MAX_PORT,
    log,
    log_exception,
    async_wrap_errors,
    field_dist,
    range_intersects,
    intersect_range,
    in_range,
)


# Convenience funcs.
# delta, nat_type
def f_is_open(n, d):
    """Return True if nat type n represents an open internet connection or a symmetric UDP firewall."""
    return n in [OPEN_INTERNET, SYMMETRIC_UDP_FIREWALL]


def f_can_predict(n, d):
    """Return True if nat type n has predictable port mappings that enable hole-punching."""
    return n in PREDICTABLE_NATS


def f_is_hard(n, d):
    """Return True if nat type n is not in the easy NAT set and its delta is neither preserving nor equal."""
    not_easy = n not in EASY_NATS
    return not_easy and d["type"] not in [PRESERV_DELTA, EQUAL_DELTA]


def delta_info(delta_type, delta_value):
    """Return a delta dict with the given type and value fields."""
    return {"type": delta_type, "value": delta_value}


def nat_info(
    nat_type=None,
    delta=None,
    map_range=None,
):
    """Build and return a NAT descriptor dict with type, delta, port range, and derived capability flags.

    The default (RESTRICT_PORT + EQUAL_DELTA) is intentionally a sane
    middle ground rather than the worst case: it lets the punch / probe
    plugins fall through to a predictable-port path when classification
    hasn't run, instead of triggering the SYMMETRIC role assignments
    that strand random_probe / udp_punch on hosts where load_nat was
    skipped (e.g. Gate(ifs=[pre_built_nic])).  Real classification via
    nic.load_nat() always overwrites this default with the measured
    result.
    """
    # Defaults.
    delta = delta or delta_info(EQUAL_DELTA, 0)
    map_range = map_range or [1, MAX_PORT]
    nat_type = nat_type or RESTRICT_PORT_NAT

    # Main NAT dic with simple lookup types.
    nat = {
        "type": nat_type,
        "delta": delta,  # type, value
        "range": map_range,  # start, stop
        "is_open": f_is_open(nat_type, delta),
        "can_predict": f_can_predict(nat_type, delta),
        "is_hard": f_is_hard(nat_type, delta),
    }

    # Setup whether this NAT type is good for concurrent punches.
    bad_delta = delta["type"] in [INDEPENDENT_DELTA, DEPENDENT_DELTA]
    nat["is_concurrent"] = nat_type in EASY_NATS or not bad_delta

    # Return results.
    return nat


def valid_mappings_len(mappings):
    """Return 1 if mappings has a valid non-empty length within MAX_MAP_NO, else 0."""
    if not len(mappings):
        return 0

    if len(mappings) > MAX_MAP_NO:
        return 0

    return 1


async def delta_test(
    stun_clients,
    test_no=8,
    threshold=5,
    concurrency=True,
):
    """
    Probe the NAT to determine what kind of port delta behaviour it exhibits.

    Symmetric NATs allocate a new mapping for each (destination, port) pair.
    This function tries to detect whether those mappings follow a predictable
    pattern, which is needed for TCP hole-punching.

    Delta types detected:
      EQUAL_DELTA     - external port equals local source port (no NAT offset).
      PRESERV_DELTA   - distance between successive mapped ports mirrors local
                        distance (port-preserving NAT).
      INDEPENDENT_DELTA - mapped ports increment by a fixed delta regardless of
                          local source port (easy to predict).
      DEPENDENT_DELTA - mapped ports increment by the same delta as local ports
                        (harder to exploit but still predictable).
      RANDOM_DELTA    - no detectable pattern; prediction is not possible.

    Note: detection of DEPENDENT_DELTA requires sequential (non-concurrent)
    probing because concurrent results arrive out of order and produce false
    negatives.  Pass concurrency=False to ensure correct results for that case.

    Port test planning:
      - start_port is chosen randomly to avoid conflicts with other test ranges.
      - Ports run from start_port to start_port + (test_no * port_dist) - 1.
    """
    assert len(stun_clients) >= test_no

    def get_start_port(port_dist, range_info=None):
        """Pick a random starting port that does not overlap any existing port-test ranges."""
        if range_info is None:
            range_info = []
        def rand_start_port():
            """Return a random port number safely below the upper bound for the test range."""
            return random.randrange(4000, MAX_PORT - (test_no * port_dist))

        # Return if no other port range to check for conflicts.
        if not range_info:
            return rand_start_port()
        new_start_port = None
        do_retry = 1
        while do_retry:
            # Try a rand port as the starting port.
            do_retry = 0
            new_start_port = rand_start_port()
            for other_range in range_info:
                # Range is other_start_port to other_end_port inclusive.
                other_dist, other_start_port = other_range
                other_end_port = other_start_port + (test_no * other_dist)

                # If it's in the same range as other_start_port retry.
                lower_bound = new_start_port >= other_start_port
                upper_bound = new_start_port <= other_end_port
                if lower_bound and upper_bound:
                    do_retry = 1
                    break

        return new_start_port

    # Create a list of tasks to get a mapping for a port range.
    def get_port_tests(start_port, port_dist=1):
        """Build a list of asyncio tasks that each send a STUN probe from a calculated source port."""
        # Return task list for tests.
        tasks = []
        for i in range(0, test_no):
            # If start is defined then calculate a list of ports.
            # Otherwise the OS assigns an unused port.
            if start_port:
                src_port = start_port + (i * port_dist)
            else:
                src_port = random.randrange(4000, MAX_PORT)

            # Get the mapping using STUN.
            async def result_wrapper(src_port, stun_idx=i):
                """Run one STUN mapping probe from src_port and return [local, mapped, socket] or None."""
                # Make sure port isn't in the reserved range.
                if src_port < 4000 and src_port != 0:
                    raise ValueError("src less than 4k in mapping behavior.")

                # Round-robin across servers so each probe hits a distinct
                # server; random.choice with replacement left ~36% unsampled.
                stun_client = stun_clients[stun_idx % len(stun_clients)]

                # Get mapping using specific source port.
                route = None
                if stun_client.interface is not None:
                    iface = stun_client.interface
                    route = iface.route(stun_client.af)
                    await route.bind(port=src_port)

                # TODO: manually chosen source ports may conflict with
                # ports already in use.  Consider checking for failure here.

                ret = await stun_client.get_mapping(pipe=route)

                if ret is None:
                    log("No stun reply in delta map")
                    return None
                local, mapped, s = ret

                # Return mapping results.
                return [local, mapped, s]

            # Allow for tests to be done concurrently.
            tasks.append(
                async_wrap_errors(
                    asyncio.wait_for(result_wrapper(src_port), 2), logging=False
                )
            )

        return tasks

    def get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results):
        """Classify STUN mapping results into delta counters (equal, preserving, independent, dependent)."""
        if results is None:
            return

        for i in range(0, len(results)):
            try:
                # Skip invalid results
                if results[i] is None:
                    continue

                # Unpack result.
                local, mapped, s = results[i]
                socks.append(s)
                if mapped is None:
                    continue

                # Set previous result if available.
                prev_result = None
                if i != 0:
                    if results[i - 1][MAPPED_INDEX] is not None:
                        prev_result = results[i - 1]

                # Preserving NAT.
                if local == mapped:
                    delta_no[EQUAL_DELTA] = delta_no.get(EQUAL_DELTA, 0) + 1

                # Comparison tests.
                if prev_result is not None:
                    # Skip invalid results.
                    prev_local = prev_result[LOCAL_INDEX]
                    prev_mapped = prev_result[MAPPED_INDEX]
                    if not prev_local or not prev_mapped:
                        continue

                    # Preserving delta if true.
                    _local_dist = abs(field_dist(local, prev_local, MAX_PORT))
                    mapped_dist = abs(field_dist(mapped, prev_mapped, MAX_PORT))
                    if mapped_dist == _local_dist:
                        # Otherwise its preserving.
                        if mapped != local:
                            preserv_dist[mapped_dist] = 1
                            delta_no[PRESERV_DELTA] = delta_no.get(PRESERV_DELTA, 0) + 1
                    else:
                        # Delta mapping dist.
                        # Plus one NAT type now here.
                        if _local_dist != 1:
                            dist_no[mapped_dist] = dist_no.get(mapped_dist, 0) + 1
                        else:
                            local_dist[mapped_dist] = local_dist.get(mapped_dist, 0) + 1
            except (ValueError, KeyError, TypeError):
                log_exception()

    # Offset names for port test results.
    LOCAL_INDEX = 0  # Source port.
    MAPPED_INDEX = 1  # External mapped port.
    socks = []

    # Used for info about port ranges used for tests.
    # [ [ dist, start_port ], ... ]
    range_info = []


    # Do first port tests with random local ports.
    tasks = get_port_tests(0)
    if concurrency:
        results = await asyncio.gather(*tasks)
    else:
        results = []
        for task in tasks:
            result = await task
            if result is not None:
                results.append(result)
    valid_round1 = sum(1 for r in results if r is not None)

    # Check for:
    #   equal delta:       src_port == mapped_port
    #   preserving delta:  dist(src_a, src_b) == dist(map_a, map_b)
    #   independent delta: dist(map_a, map_b) == constant delta n
    delta_no = {}
    dist_no = {}
    preserv_dist = {}
    local_dist = {}

    # Close previous sockets.
    get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results)
    for p in socks:
        if p is None:
            continue

        await p.close()

    socks = []


    # See if any of the above tests succeeded.
    test_names = [EQUAL_DELTA, PRESERV_DELTA]
    if len(preserv_dist) <= 1:
        test_names = [EQUAL_DELTA]

    for test_name in test_names:
        if test_name not in list(delta_no.keys()):
            continue

        no = delta_no[test_name]
        if no >= threshold:
            return delta_info(test_name, 0)
    for port_dist in list(dist_no.keys()):
        no = dist_no[port_dist]
        if no >= threshold:
            return delta_info(INDEPENDENT_DELTA, port_dist)

    # Check for dependent delta: requires that the local source port also
    # increments by the same delta (dist(map_a, map_b) == dist(local_a, local_b)).
    delta_no = {}
    dist_no = {}
    preserv_dist = {}
    local_dist = {}

    # Get mapping results for fixed delta.
    start_port = get_start_port(1, range_info)
    tasks = get_port_tests(start_port)
    if concurrency:
        results = await asyncio.gather(*tasks)
    else:
        results = []
        for task in tasks:
            result = await task
            results.append(result)
    valid_round2 = sum(1 for r in results if r is not None)

    get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results)

    # Check for deltas that satisfy success threshold.
    for port_dist in list(local_dist.keys()):
        no = local_dist[port_dist]
        if no >= threshold:
            return delta_info(DEPENDENT_DELTA, port_dist)

    # Return delta value.
    return delta_info(RANDOM_DELTA, 0)


def nats_intersect(
    our_nat, their_nat, test_no
):
    """
    Return the port range both NATs can agree on for test probes.

    Some NATs (e.g. Starlink's default router) only allocate mappings from
    a fixed sub-range of ports (e.g. 35000–65535), possibly to reduce
    visibility on port scans.  When planning hole-punch tests we need a
    range that both sides can reach.

    If an intersection exists and is at least test_no ports wide, it is
    returned.  Otherwise our_nat's full range is used as a fallback.
    Port ranges below 1024 are always shifted up to 2000 to avoid requiring
    root/admin privileges.
    """
    # Calculate intersection range.
    is_intersect = range_intersects(our_nat["range"], their_nat["range"])
    if is_intersect:
        # A range that represents an overlapping portion.
        # Between our[range] and their[range] if any.
        r = intersect_range(our_nat["range"], their_nat["range"])

        # If range is long enough then use it.
        range_no = r[1] - r[0]
        if range_no >= test_no:
            use_range = r
        else:
            use_range = our_nat["range"]
    else:
        use_range = our_nat["range"]

    # Ensure bind ports don't end up in low port ranges.
    if use_range[0] <= 1024:
        use_range[0] = 2000
        if use_range[0] >= use_range[1]:
            raise ValueError("Can't find intersecting port range.")

    return use_range


def nats_can_predict(our_nat, their_nat):
    """
    Validate that mapping prediction is possible given the two NAT profiles.

    Returns the port that should be used as a reply port for STUN probes
    (1 = use STUN port 3478, 0 = use an arbitrary port).
    Raises if the NAT combination makes prediction provably impossible.
    """
    # Handle restricted port NATs (RESTRICT_PORT_NAT).
    our_strict = our_nat["type"] == RESTRICT_PORT_NAT
    other_strict = their_nat["type"] == RESTRICT_PORT_NAT
    if our_strict and other_strict:
        # Error scenario for two strict port NATs with rand deltas.
        our_rand_delta = our_nat["delta"]["type"] == RANDOM_DELTA
        their_rand_delta = their_nat["delta"]["type"] == RANDOM_DELTA
        if our_rand_delta or their_rand_delta:
            raise ValueError("Two strict port nats need non-rand deltas.")

    # If either side is port restrict make sure its partner can satisfy reply port.
    use_stun_port = 0
    if our_strict or other_strict:
        for nats in [[our_nat, their_nat], [their_nat, our_nat]]:
            # Switch which side is restricted.
            # Both may be restricted -- in which case both need non-rand delta.
            strict, unrestrict = nats
            if unrestrict["type"] == RESTRICT_PORT_NAT:
                strict, unrestrict = unrestrict, strict

            # If strict side has rand delta and partner cant satisfy reply port.
            # There are multiple ways to satisfy the reply port which are checked.
            # Raise an error condition if certain failure.
            strict_rand_delta = strict["delta"]["type"] == RANDOM_DELTA
            if strict_rand_delta and unrestrict["is_hard"]:
                raise ValueError("Unable to satisfy mapping for strict port type.")

            # The reply port here is the STUN port as they use STUN to get a mapping.
            # Unable to satisfy reply port due to allocation range.
            if strict_rand_delta and not in_range(STUN_PORT, unrestrict["range"]):
                raise ValueError("Can't support reply port 3478 for strict NAT.")

            # Use STUN port (3478) when generating probe mappings.
            # STUN's port is above 1024, so no root/admin is required — which
            # is lucky, because restricted-port NATs need us to match the
            # exact port the peer expects to receive replies on.
            if strict_rand_delta:
                use_stun_port = 1

    return use_stun_port
