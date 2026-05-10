"""
Without magic cookie = 3489 mode
    - cips / ports / change requests
With magic cookie = RFC 5389 >= mode
    - no change requests

Original stun code was based on https://github.com/talkiq/pystun3 but through trial-and-error I found that this
code incorrectly handles magic cookies, xor encoding,
and has many other issues.

The current code is based on extensive modifications to the TURN proxy code found in this repo: https://github.com/trichimtrich/turnproxy which includes a very good
parser for STUN messages. I've merged in logic from
talkiqs fork and my bug fixes for NAT detection.

changes:
- full async support
- add more stun servers
- test that they all work
- improve error checking
- add ipv6 support
- improve commenting
- fix some smol bugs (including nat test bugs)
- load balancing to avoid overloading
- result average support to avoid invalid servers
- separate list of hosts that support ipv6 for less failures on ipv6
- TCP support (for get mappings)
- delta n test (some nats have predictable mappings and assign then a delta apart)
- added better checking for 'change IPs' and made a new address family for hosts that return correct change ip responses. the nat determination code needs to use these hosts. for regular 'get wan ip' and 'get port mapped' lookups you can use the change hosts or the mapping hosts (larger list)
- proper support for RFC 3489 and RFC 5389 >=

Note 1: Some of the response times for DNS lookups to the STUN servers in
this module are on the order of 1 second or higher -- an astronomical
amount of time for a network. I have tried to use concurrency patterns
where ever possible to avoid delaying other, faster lookups.4

Note 2: I've read the STUN RFC and it seems to indicate that many of the fields in the protocol format take place over byte boundaries. Yet the client code here works on all the servers I've tested it on and doesn't make these assumptions. It's possible the spec is wrong or maybe my code just won't work with particular features of the STUN protocol. No idea.

TODO: sort the hosts by how fast they respond to a STUN request from domain resolution to reply time.
TODO: It seems that this is a pattern that reoccurs in several functions.
The general form might also make sense to add to the Net module.
TODO: Refactor code. The code in this module offers many good features but the code reflects too much cruft. It could do with a good cleanup.
"""

import asyncio
from ...errors import ErrorFeatureDeprecated
from ...utility.utils import (
    async_wrap_errors,
    cancel_tasks,
    log,
    log_exception,
    strip_none,
)
from ...utility.pattern_factory import concurrent_first_agree_or_best
from ...net.net_defs import IP4, IP6, NET_CONF, UDP
from ...net.net_utils import ip_norm
from ...net.address import resolv_dest
from ...net.pipe.pipe import Pipe
from ...net.bind.bind import Bind
from .stun_defs import RFC3489, RFC5389, STUNAttrs
from .stun_utils import get_stun_reply
from ...servers import get_infra
from ...nic.route.route import Route


class STUNClient:
    """Sends STUN requests to a single server and returns mapping, WAN IP, or change-address replies."""

    def __init__(
        self,
        af,
        dest,
        nic,
        proto=UDP,
        mode=RFC3489,
        conf=NET_CONF,
    ):
        self.dest = dest
        self.interface = nic
        self.af = af
        self.proto = proto
        self.mode = mode
        self.conf = conf

    # Boilerplate to get a pipe to the STUN server.
    async def _get_dest_pipe(self, unknown):
        """Return an open Pipe to the STUN server, reusing an existing Pipe/Route or opening a new one."""
        # Already open pipe.
        if isinstance(unknown, Pipe):
            return unknown

        # Open a new con to STUN server.
        route = unknown
        if unknown is None:
            route = self.interface.route(self.af)
            await route.bind()

        # Route passed in already bound.
        # Upgrade it to a pipe.
        if isinstance(unknown, Route):
            route = unknown
        if isinstance(unknown, Bind):
            route = unknown

        assert route

        # Otherwise use details to make a new pipe.
        self.dest = await resolv_dest(self.af, self.dest, self.interface)
        return await Pipe(self.proto, self.dest, route, conf=self.conf).connect()

    # Returns a STUN reply based on how client was setup.
    async def get_stun_reply(
        self, pipe=None, attrs=None
    ):
        """Send a STUN binding request with optional attributes and return the parsed reply."""
        if attrs is None:
            attrs = []
        caller_pipe = pipe
        pipe = await self._get_dest_pipe(pipe)
        try:
            return await get_stun_reply(self.mode, self.dest, self.dest, pipe, attrs)
        finally:
            if caller_pipe is None and pipe is not None:
                await pipe.close()

    # Use a different port for the reply.
    async def get_change_port_reply(
        self, ctup, pipe=None
    ):
        """
        With RFC 5389 the change request feature was deprecated.
        Servers aren't required to support it and I've yet to see any that do.
        """
        # Sanity check against expectations.
        if self.mode != RFC3489:
            error = "STUN change port only supported in RFC3489 mode."
            raise ErrorFeatureDeprecated(error)

        # Expect a reply from this address.
        reply_addr = (
            # The IP stays the same.
            self.dest[0],
            # But expect the reply on the change port.
            ctup[1],
        )

        # Flag to make the port change request.
        caller_pipe = pipe
        pipe = await self._get_dest_pipe(pipe)
        try:
            return await get_stun_reply(
                self.mode,
                self.dest,
                reply_addr,
                pipe,
                [[STUNAttrs.ChangeRequest, b"\0\0\0\2"]],
            )
        finally:
            if caller_pipe is None and pipe is not None:
                await pipe.close()

    # Use a different IP and port for the reply.
    async def get_change_tup_reply(
        self, ctup, pipe=None
    ):
        """Send an RFC 3489 change-IP-and-port request and return the reply from ctup."""
        # Sanity check against expectations.
        if self.mode != RFC3489:
            error = "STUN change port only supported in RFC3489 mode."
            raise ErrorFeatureDeprecated(error)

        # Flag to make the tup change request.
        caller_pipe = pipe
        pipe = await self._get_dest_pipe(pipe)
        try:
            return await get_stun_reply(
                self.mode, self.dest, ctup, pipe, [[STUNAttrs.ChangeRequest, b"\0\0\0\6"]]
            )
        finally:
            if caller_pipe is None and pipe is not None:
                await pipe.close()

    # Return only your remote IP.
    async def get_wan_ip(self, pipe=None):
        """Return the normalised WAN IP string reported by the STUN server, or None on failure."""
        caller_pipe = pipe
        pipe = await self._get_dest_pipe(pipe)
        try:
            reply = await get_stun_reply(self.mode, self.dest, self.dest, pipe)

            if hasattr(reply, "rtup"):
                return ip_norm(reply.rtup[0])
        finally:
            # Only close the pipe if we opened it ourselves.
            if caller_pipe is None and pipe is not None:
                await pipe.close()

    # Return information on your local + remote port.
    # On success the pipe is intentionally left open and returned to the
    # caller so it can be reused for hole-punching.  On failure the pipe
    # is closed here so it does not leak.
    async def get_mapping(
        self, pipe=None
    ):
        """Return (local_port, mapped_port, pipe) for this connection, leaving the pipe open for hole-punching."""
        caller_supplied_pipe = pipe is not None
        pipe = await self._get_dest_pipe(pipe)
        try:
            reply = await get_stun_reply(self.mode, self.dest, self.dest, pipe)

            ltup = reply.pipe.sock.getsockname()
            if hasattr(reply, "rtup"):
                # Pipe ownership transfers to the caller.
                return (ltup[1], reply.rtup[1], reply.pipe)

            # Server replied but did not include a mapped-address attribute.
            # Close the pipe we opened (unless the caller supplied it).
            if not caller_supplied_pipe:
                await pipe.close()
            return None
        except (OSError, ConnectionError, asyncio.TimeoutError):
            if not caller_supplied_pipe:
                try:
                    await pipe.close()
                except (OSError, asyncio.TimeoutError):
                    pass
            raise


def get_stun_clients(
    af,
    max_agree,
    interface,
    mode,
    proto=UDP,
    servs=None,
    conf=NET_CONF,
    attempt=0,
):
    """Build and return up to max_agree STUNClient instances for the given AF, mode, and protocol."""
    # Copy random STUN servers to use.
    if servs is None:
        if mode == RFC3489:
            name = "STUN(test_nat)"

        if mode == RFC5389:
            name = "STUN(see_ip)"

        serv_list = get_infra(af, proto, name, no=max_agree, attempt=attempt)
    else:
        serv_list = servs

    stun_clients = []
    for serv_info in serv_list:
        serv_info = serv_info[0]
        try:
            dest = (serv_info["ip"], serv_info["port"])
            stun_client = STUNClient(
                af,
                dest,
                interface,
                proto=proto,
                mode=mode,
                conf=conf,
            )

            stun_clients.append(stun_client)
        except (ValueError, KeyError):
            log_exception()
            log("unexpected exception in get_stun_client helper")

        if len(stun_clients) >= max_agree:
            break

    # Check that its the correct type.
    stun_clients = strip_none(stun_clients)
    for client in stun_clients:
        assert isinstance(client, STUNClient)

    return stun_clients


async def get_n_stun_clients(
    af,
    n,
    interface,
    mode,
    proto=UDP,
    limit=5,
    conf=NET_CONF,
):
    """Return n verified STUNClient instances that each successfully returned a mapping, using hedged probing."""
    # Try a single STUN candidate; close the probe pipe on success.
    async def try_one(stun):
        """Probe a single STUNClient with get_mapping and return it on success, or None on failure."""
        try:
            out = await stun.get_mapping()
            if out is not None:
                # Close the probe pipe; caller manages their own pipes.
                if len(out) >= 3 and out[2] is not None:
                    await out[2].close()
                return stun
        except asyncio.CancelledError:
            raise
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
        return None

    # Hedged requests: try candidates one at a time but stagger launches so
    # we don't wait for a full TCP timeout before moving on.  A new candidate
    # is only started if the previous one hasn't responded within HEDGE_DELAY.
    # This avoids the original O(limit × timeout) worst case while keeping
    # total connections close to 1 on a healthy network.
    #
    # IPv6 probes take longer than IPv4 (tunnels, 6in4, smaller server pool,
    # wider geographic spread) so the hedge window is wider for AF_INET6.
    #
    # get_infra uses a deterministic RNG seeded by `attempt`, so each
    # worker is passed a distinct attempt index to ensure they sample
    # different server pools rather than all querying the same servers.
    HEDGE_DELAY = 1.5 if af == IP6 else 0.5

    async def worker(attempt):
        """Try STUN candidates in hedged order and return the first one that responds successfully."""
        candidates = get_stun_clients(
            af=af,
            max_agree=limit,
            mode=mode,
            interface=interface,
            proto=proto,
            conf=conf,
            attempt=attempt,
        )
        if not candidates:
            return None

        tasks = []
        winner = None
        try:
            for candidate in candidates:
                t = asyncio.ensure_future(try_one(candidate))
                tasks.append(t)

                # Wait briefly; if this candidate responds in time we're done
                # and never launch the next one.
                done, _ = await asyncio.wait({t}, timeout=HEDGE_DELAY)
                if done:
                    # The task may have completed with an exception (e.g.
                    # CancelledError from an external cancellation arriving
                    # while asyncio.wait was running).  Guard t.result() so
                    # a single bad candidate cannot crash the whole worker.
                    try:
                        result = t.result()
                    except (asyncio.CancelledError, Exception):
                        result = None
                    if result is not None:
                        winner = result
                        break
                # No result yet — loop and launch the next candidate in parallel.
        finally:
            await cancel_tasks(tasks)

        # If no candidate won during the staggered loop, check whether any
        # of the already-launched tasks finished successfully.
        if winner is None:
            for t in tasks:
                if t.done() and not t.cancelled():
                    try:
                        result = t.result()
                        if result is not None:
                            winner = result
                            break
                    except (Exception, asyncio.CancelledError):
                        pass
        return winner

    # Create list of worker tasks for concurrency (faster.)
    # Pass a distinct attempt index per worker so get_infra's deterministic
    # RNG seeds differently, giving each worker a different server pool.
    tasks = []
    for i in range(0, n):
        tasks.append(async_wrap_errors(worker(attempt=i)))

    # Run tasks and return results.
    return strip_none(
        await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )
    )


async def run_stun_client():
    """
    Xport ^ txid = port
    """

    """
    buf = b''
    buf = b'\x01\x01\x000!4Q#\x95\xb2/\xb8@\xa5\xb9\x99[\xe9\xda\xbb\x00\x01\x00\x08\x00\x01\xe1&\x9f\xc4\xc1\xb7\x00\x04\x00\x08\x00\x01\r\x96Xc\xd3\xd8\x00\x05\x00\x08\x00\x01\r\x97Xc\xd3\xd3\x80 \x00\x08\x00\x01\xc0\x12\xbe\xf0\x90\x94'
    ret = stun_proto(buf, IP4)
    print(ret)

    return

    from .interface import Interface

    await Interface()
    a = ("stunserver.stunprotocol.org", 3478)
    s = STUNClientRef(a)
    r = await s.get_stun_reply()
    print(r.rtup)
    print(r.stup)
    print(r.ctup)
    print(r.pipe.sock)

    c1 = await s.get_change_port_reply(r.ctup)
    print("change port reply = ")
    print(c1)
    print(c1.rtup)
    print(c1.stup)

    c1 = await s.get_change_tup_reply(r.ctup)
    print("change tup reply = ")
    print(c1)
    print(c1.rtup)
    print(c1.stup)

    await r.pipe.close()
    """


async def run_con_stun_client():
    from .interface import Interface

    af = IP4
    proto = UDP
    i = await Interface()
    stun_clients = []
    tasks = []
    servers = get_infra(af, proto, "STUN(get_mapping)")
    for n in range(0, min(5, len(servers))):
        dest = (
            servers[n]["primary"]["ip"],
            servers[n]["primary"]["port"],
        )
        stun_client = STUNClient(dest, i, proto=proto)
        stun_clients.append(stun_client)
        task = stun_client.get_wan_ip()
        tasks.append(task)

    min_agree = 2
    out = await concurrent_first_agree_or_best(min_agree, tasks, timeout=2)

    print(out)

    await asyncio.sleep(2)


if __name__ == "__main__":
    pass
    # async_test(change_server_bind_experiment)
