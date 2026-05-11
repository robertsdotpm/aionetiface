"""
When using UDP in network programming its common to write
code so that it has simple loops to retry sending packets if
no response is received. The problem is: if any packets are lost
the time spent waiting keeps accumulating to the cost of a round-trip.

The problem is made worse when you consider slow-downs in DNS and
the often unreliable nature of relying on community servers for
STUN code. If one is not careful they quickly end up with an
algorithm that is prohibitively slow in the best case and quite
unreliable in the worst case.

The original algorithm for doing STUN tests for RFC 3489 used
incremental tests and was very brittle. However -- due to the
nature of how these tests work -- it became clear to me that it was
possible to paralyze the tests into two main phases if a STUN
server's primary and secondary IP were known beforehand.

Phase 1 tests for [open NAT and full cone] while phase 2 tests for
[restrict ip and restrict port] behaviors. The algorithm here is designed to run across multiple public servers where it creates races among
all servers to test a routes NAT. The result is you end up with
the fastest possible determination of NAT behaviors while also
building in safe-guards against packet-loss, inconsistent results, misconfigurations, and slow network conditions.
"""

import asyncio
from ...utility.utils import (
    async_wrap_errors,
    ip_f,
    log,
    fstr,
)
from ...errors import ErrorCantLoadNATInfo
from ...net.net_defs import IP4, IP6, UDP
from ...protocol.stun.stun_defs import (
    RFC3489,
    RFC5389,
    STUN_CHANGE_NONE,
    STUN_CHANGE_PORT,
    STUN_CHANGE_BOTH,
)
from ...protocol.stun.stun_client import STUNClient, get_stun_clients
from ...protocol.stun.stun_utils import stun_reply_to_ret_dic
from ...servers import get_infra
from ...net.pipe.pipe import Pipe
from .nat_defs import (
    BLOCKED_NAT,
    FULL_CONE,
    NA_DELTA,
    OPEN_INTERNET,
    RANDOM_DELTA,
    RESTRICT_NAT,
    RESTRICT_PORT_NAT,
    SYMMETRIC_NAT,
)
from .nat_utils import delta_info, delta_test, nat_info


# Constants for a NAT test.
NAT_TEST_NO = 5
NAT_TEST_TIMEOUT = 0.5

# STUN payload to send, Send IP, send port, reply IP, reply port
# Shows order of RFC 3489 NAT enumeration sets.
NAT_TEST_SCHEMA = [
    # Detects: open NAT.
    # dest: primary, primary. reply: primary, primary
    [STUN_CHANGE_NONE, 0, 0, 0, 0],
    # Detects: full cone NAT.
    # Change both reply IP and port.
    # dest: primary, primary. reply: secondary, secondary
    [STUN_CHANGE_BOTH, 0, 0, 3, 3],
    # Detects: non-symmetric NAT.
    # dest secondary, primary. reply: secondary, primary
    [STUN_CHANGE_NONE, 2, 2, 2, 0],
    # Detects: between restrict and port restrict.
    # Change only the reply port.
    # dest: secondary, primary. reply: secondary, secondary.
    [STUN_CHANGE_PORT, 2, 2, 3, 3],
]


async def nat_test_exec(
    dest_addr,
    reply_addr,
    payload,
    mode,
    pipe,
    q,
    test_coro,
):
    stun_client = STUNClient(pipe.route.af, dest_addr, pipe.route.interface, mode=mode)
    if payload == STUN_CHANGE_NONE:
        reply = await stun_client.get_stun_reply(pipe)
    if payload == STUN_CHANGE_PORT:
        reply = await stun_client.get_change_port_reply(reply_addr, pipe)
    if payload == STUN_CHANGE_BOTH:
        reply = await stun_client.get_change_tup_reply(reply_addr, pipe)

    ret = await stun_reply_to_ret_dic(reply)

    # Valid reply.
    if ret is not None and not isinstance(ret, tuple):
        q.append(ret)
        return await test_coro(ret, pipe)

    return None


async def nat_test_workers(
    pipe,
    q,
    test_index,
    test_coro,
    servers,
    test_no,
):
    # Make list of coroutines to do this NAT tests.
    workers = []
    for server_no in range(0, min(test_no, len(servers))):

        async def worker(server_no):
            # Packets will go to this destination.
            # Send to, expect from.
            addrs = []
            for x in range(0, 2):
                # Determine which fields to use for IP and port.
                schema = NAT_TEST_SCHEMA[test_index][(x * 2) + 1 : (x * 2) + 3]
                ip_type = schema[0]
                port_type = schema[1]

                # Resolve IP and port as an Address.
                addrs.append(
                    (
                        servers[server_no][ip_type]["ip"],
                        servers[server_no][port_type]["port"],
                    )
                )

            # Run the test and return the results.
            payload = NAT_TEST_SCHEMA[test_index][0]
            return await async_wrap_errors(
                nat_test_exec(
                    # Send to and expect from.
                    addrs[0],
                    addrs[1],
                    # Type of STUN request to send.
                    payload,
                    # Mode to use for stun server.
                    RFC3489,
                    # Pipe to reuse for UDP.
                    pipe,
                    # Async queue to store the results.
                    q,
                    # Test-specific code.
                    test_coro,
                ),
                logging=False,
            )

        workers.append(worker(server_no))

    return workers


"""
If a NAT uses the same 'mapping' (external IP and port) given
the same internal (IP and port) even when destinations are
different then it's considered non-symmetric. The software
proceeds to determine the exact conditions for which mappings
can be reused when using the same bind tuples.
"""


def non_symmetric_check(q_list):
    # Test 1 and 3.
    q1 = q_list[0]
    q3 = q_list[2]

    # Not enough data to know.
    if not len(q1) or not len(q3):
        return False

    # NAT reuses mappings given same internal (ip and port)
    port_check = q1[0]["rport"] == q3[0]["rport"]
    ip_check = ip_f(q1[0]["rip"]) == ip_f(q3[0]["rip"])
    if port_check and ip_check:
        return True

    # Otherwise return False.
    return False


"""
If there's no replies in any of the NAT test lists then
assume that this means there's a firewall and return False.
"""


def no_stun_resp_check(q_list):
    for i in range(0, 4):
        if len(q_list[i]):
            return False

    return True


async def fast_nat_test(
    pipe, test_no=NAT_TEST_NO, timeout=NAT_TEST_TIMEOUT
):
    # Use a random portion of change servers for
    # the NAT test.
    serv_list = get_infra(pipe.route.af, UDP, "STUN(test_nat)", no=test_no)
    test_servers = serv_list

    print("[NAT-LOAD] fast_nat_test: enter test_no={0} timeout={1} servers={2}".format(
        test_no, timeout, len(test_servers),
    ), flush=True)

    # Store STUN request results here.
    # n = index of test e.g. [0] = test 1.
    q_list = [[], [], [], []]
    q_list.append(SYMMETRIC_NAT)

    # Open NAT type.
    async def test_one(ret, test_pipe):
        source_ip = test_pipe.route.nic()
        if ip_f(ret["rip"]) == ip_f(source_ip):
            return OPEN_INTERNET

    # Full cone NAT.
    async def test_two(ret, test_pipe):
        # Test 2 may arrive before test 1.
        # In this case: test 1 takes priority over test 2.
        return await test_one(ret, test_pipe) or FULL_CONE

    # Whitelist of dest (IP and port).
    async def test_three(ret, test_pipe):
        if non_symmetric_check(q_list):
            q_list[4] = RESTRICT_PORT_NAT

    # Whitelist of dest (IP).
    async def test_four(ret, test_pipe):
        return RESTRICT_NAT

    """
    All tests in sub_test_a are tried then sub_tests_b.
    Both sub test lists can't be run concurrently
    due to how NATs function with white listing.
    """
    test_index = 0
    for sub_test in [[test_one, test_two], [test_three, test_four]]:
        # Get a list of workers for first two NAT tests.
        workers = []
        for test_coro in sub_test:
            # Build list of coroutines to run these NAT tests.
            # Test funcs are run on receiving a STUN response.
            workers += await nat_test_workers(
                pipe, q_list[test_index], test_index, test_coro, test_servers, test_no
            )

            # Keep track of test offset.
            test_index += 1

        # Run NAT sub tests.
        try:
            # First result in or timeout.
            for task in asyncio.as_completed(workers, timeout=timeout):
                ret = await task
                if ret is not None:
                    print("[NAT-LOAD] fast_nat_test: early-exit ret={0} q_lens={1}".format(
                        ret, [len(q_list[i]) for i in range(4)],
                    ), flush=True)
                    return ret
        except asyncio.TimeoutError:
            print("[NAT-LOAD] fast_nat_test: sub-test timed out q_lens={0}".format(
                [len(q_list[i]) for i in range(4)],
            ), flush=True)
            continue

    # All tests timed out.
    # Determine return value.
    print("[NAT-LOAD] fast_nat_test: all sub-tests done q_lens={0} fallback={1}".format(
        [len(q_list[i]) for i in range(4)], q_list[-1],
    ), flush=True)
    if no_stun_resp_check(q_list):
        print("[NAT-LOAD] fast_nat_test: -> BLOCKED_NAT (no STUN replies)", flush=True)
        return BLOCKED_NAT
    # Symmetric NAT or RESTRICT_PORT_NAT.
    print("[NAT-LOAD] fast_nat_test: -> q_list[-1]={0}".format(q_list[-1]), flush=True)
    return q_list[-1]


async def nic_load_nat(
    nic,
    nat_tests=5,
    delta_tests=12,
    servs=None,
    timeout=4,
):
    # IPv6-only NICs have no NAT — treat as open internet with no delta.
    # Returning SYMMETRIC_NAT here was wrong: it caused pair_has_symmetric
    # to exclude all IPv6-only pairs from punch plugins.
    if IP4 not in nic.supported():
        return OPEN_INTERNET, delta_info(NA_DELTA, 0)
    af = IP4

    # Copy random STUN servers to use.
    test_no = max(nat_tests, delta_tests)
    stun_clients = get_stun_clients(af, test_no, nic, RFC5389, proto=UDP, servs=servs)

    print("[NAT-LOAD] nic_load_nat: enter nic={0} af={1} nat_tests={2} delta_tests={3} timeout={4}".format(
        getattr(nic, "name", "?"), af, nat_tests, delta_tests, timeout,
    ), flush=True)

    # Pipe is used for NAT tests using multiplexing.
    # Same socket, different dests, TXID ordered.
    route = await nic.route(af).bind()
    try:
        pipe = Pipe(UDP, None, route)
        await pipe.connect()
    except (OSError, ConnectionError) as e:
        print("[NAT-LOAD] nic_load_nat: pipe open failed: {0} {1}".format(
            type(e).__name__, e,
        ), flush=True)
        raise ErrorCantLoadNATInfo("Unable to start pipe for load nat.")

    # Run delta test.
    nat_type, delta = await asyncio.gather(
        *[
            # Fastest fit wins.
            async_wrap_errors(
                fast_nat_test(
                    pipe,
                    test_no=nat_tests,
                ),
                timeout=timeout,
            ),
            # Concurrent -- 12 different hosts
            # Threshold of 5 for consensus.
            async_wrap_errors(
                delta_test(
                    stun_clients,
                    test_no=delta_tests,
                    threshold=int(delta_tests / 2) - 1,
                ),
                timeout=timeout,
            ),
        ]
    )

    # Cleanup NAT test pipe.
    if pipe is not None:
        await pipe.close()

    # Sanity check nat / delta details.
    log(fstr(
        "nic_load_nat: nic={0} af={1} nat_type={2} delta={3}",
        (nic.name, af, nat_type, delta),
    ))
    print("[NAT-LOAD] nic_load_nat: gather done nat_type={0} delta={1}".format(
        nat_type, delta,
    ), flush=True)
    if None in [nat_type, delta]:
        print("[NAT-LOAD] nic_load_nat: -> raise ErrorCantLoadNATInfo (None in result)", flush=True)
        raise ErrorCantLoadNATInfo("Unable to load nat.")

    print("[NAT-LOAD] nic_load_nat: -> success nat_type={0} delta_type={1}".format(
        nat_type, delta.get("type") if isinstance(delta, dict) else delta,
    ), flush=True)
    return nat_type, delta


