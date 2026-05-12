"""
When you're writing server code you are constantly restarting
the process and making changes. This can lead to processes
staying open / lingering in the background that are still listening
on the same port. When doing hacks to reuse ports rapidly for
testing it can lead to very unexpected behavior. Like the
background server (that you don't realize still exists) ends
up stealing all the packets and then you waste hours wndering
why your networking code isn't working.

TODO: Better zombie process detection.
"""

import asyncio
import copy
import os
import pathlib
import re
from ..utility.utils import (
    async_test,
    async_wrap_errors,
    bind_str,
    dict_child,
    fstr,
    log,
    log_exception,
    strip_none,
)
from .net_defs import IP4, IP6, TCP, UDP, VALID_AFS, VALID_ANY_ADDR, NET_CONF
from .net_utils import avoid_time_wait, ip_norm
from .ip_range import ipr_norm
from .pipe.pipe import Pipe
from ..nic.interface import Interface
from ..install import get_aionetiface_install_root


DAEMON_CONF = dict_child({"reuse_addr": True}, NET_CONF)


async def is_serv_listening(proto, listen_route):
    """
    Return True if there is already a server listening on listen_route.

    For TCP, a quick connection attempt is made to the listen address.
    For UDP the check is skipped (returns False) because UDP is connectionless
    and a bound socket does not imply an active listener.
    """
    # UDP is connectionless.
    # A Pipe socket doesn't mean its open.
    if proto == UDP:
        return False

    # Destination address details for serv.
    listen_ip = listen_route.bind_tup()[0]
    listen_port = listen_route.bind_tup()[1]
    if not listen_port:
        return False

    # Route to connect to serv.
    route = listen_route.interface.route(listen_route.af)
    await route.bind()

    # If listen was on all then the dest IP will be wrong.
    if listen_ip in VALID_ANY_ADDR:
        listen_ip = "localhost"

    # Try make pipe to the server socket.
    dest = (listen_ip, listen_port)
    try:
        pipe = await Pipe(proto, dest, route).connect()
        await pipe.close()
        return True
    except (OSError, ConnectionError, asyncio.TimeoutError):
        return False


def get_serv_lock(
    af, proto, serv_port, serv_ip, install_path
):
    """
    Return a filesystem-based inter-process lock for the given server endpoint.

    The lock file is keyed on (af, proto, port, ip) so that two processes
    trying to start the same server will conflict.  If a daemon exited
    uncleanly the lock file may be stale; the caller should treat a failed
    acquire as a zombie-process condition.

    Returns None if the lock library is unavailable.
    """
    # Make install dir if needed.
    try:
        pathlib.Path(install_path).mkdir(parents=True, exist_ok=True)
    except OSError:
        log_exception()

    # Main path files.
    af = "v4" if af == IP4 else "v6"
    proto = "tcp" if proto == TCP else "udp"
    serv_ip = ip_norm(serv_ip)
    serv_ip = re.sub("[:]+", "_", serv_ip)
    serv_ip = serv_ip.replace(".", "_")
    if not len(serv_ip):
        serv_ip = "0"
        log("Serv ip in get serv lock is len 0")

    pidfile_path = os.path.realpath(
        os.path.join(
            install_path,
            # TODO: use hashes here instead..
            fstr(
                "{0}_{1}_{2}_{3}_pid.txt",
                (
                    af,
                    proto,
                    serv_port,
                    serv_ip,
                ),
            ),
        )
    )

    # TODO: use a more portable approach that's safer.
    try:
        from ..vendor.fasteners import InterProcessLock

        return InterProcessLock(pidfile_path)
    except (ImportError, OSError):
        return None


async def for_server_in_daemon(daemon, func):
    """
    Call func(server) concurrently for every server pipe registered in daemon.

    Errors from individual calls are collected rather than propagated so that
    one failing server does not prevent the others from being visited.
    """
    tasks = []
    for af in VALID_AFS:
        for proto in [TCP, UDP]:
            for port in daemon.servers[af][proto]:
                for ip in daemon.servers[af][proto][port]:
                    server = daemon.servers[af][proto][port][ip]
                    tasks.append(async_wrap_errors(func(server)))

    await asyncio.gather(*tasks, return_exceptions=True)


class Daemon:
    """Manages one or more listening server pipes and routes incoming messages to callbacks."""

    def __init__(self, conf=DAEMON_CONF):
        # Special net conf for daemon servers.
        self.conf = conf

        # Used for storing PID lock files.
        self.install_path = get_aionetiface_install_root()

        # AF: proto: port: ip: pipe_events.
        self.servers = {
            IP4: {TCP: {}, UDP: {}},
            IP6: {TCP: {}, UDP: {}},
        }

    # On message received (placeholder.)
    async def msg_cb(self, msg, client_tup, pipe):
        """Default message handler that echoes received data back to the sender."""
        await pipe.send(msg, client_tup)

    # On connection success (placeholder.)
    # Ran when a connection is first created for a client.
    # Just like connection_made in protocol classes.
    def up_cb(self, msg, client_tup, pipe):
        """Default connection-established handler; override in subclasses to react to new clients."""

    async def add_listener(self, proto, route):
        """
        Attach a server listening pipe to this daemon.

        The route must already be resolved (bound address known).
        Used internally by listen_all and listen_loopback.
        """
        # Ensure route is bound.
        assert route.resolved

        # bind() accepts port=0 to let the OS choose, or a specific port.
        # A specific port may conflict with a previous run that didn't exit
        # cleanly, so we detect that before trying to bind.
        bind_port = route.bind_port

        # Check if server is already listening.
        lock = None
        ip, port = route.bind_tup()[:2]
        if bind_port:
            # Detect zombie servers.
            lock = get_serv_lock(route.af, proto, port, ip, self.install_path)
            if lock is not None:
                if not lock.acquire(blocking=False):
                    error = fstr(
                        "{0}:{1} zombie pid",
                        (
                            proto,
                            bind_str(route),
                        ),
                    )
                    raise OSError(error)

            # A simple TCP con is made to TCP servers to check if it's
            # still listening before binding.
            is_listening = await async_wrap_errors(is_serv_listening(proto, route))

            # If it is then raise exception.
            if is_listening:
                error = fstr(
                    "{0}:{1} listen conflict.",
                    (
                        proto,
                        bind_str(route),
                    ),
                )
                raise OSError(error)

        # Start a new server listening.
        pipe = await Pipe(proto, None, route, conf=self.conf).connect(
            self.msg_cb, self.up_cb
        )

        assert pipe is not None

        # TIME_WAIT: after a server closes, the OS holds the port for
        # several minutes.  Restarting with the same ports would normally
        # fail with EADDRINUSE.  avoid_time_wait() sets SO_LINGER=0 to
        # skip that wait, which is acceptable in a test/dev environment.
        avoid_time_wait(pipe)

        # Only one instance of this service allowed.
        if bind_port:
            pipe.proc_lock = lock

        # A zero bind port means the OS picked the port.  Read it back
        # so we can store the pipe under the correct quad-tuple.
        # No proc_lock is created because OS-chosen ports never conflict.
        if not bind_port:
            try:
                port = pipe.sock.getsockname()[1]
            except OSError:
                log_exception()
                raise

        # Store the server pipe.
        self.servers[route.af][proto].setdefault(port, {})
        self.servers[route.af][proto][port][ip] = pipe
        return (port, pipe)

    async def listen_all(self, proto, port, nic):
        """
        Listen on all addresses supported by nic.

        Creates one socket per supported address family.  An IPv6 dual-stack
        option exists but is not guaranteed across platforms, so two sockets
        are used instead.
        """
        outs = []
        for af in nic.supported():
            route = nic.route(af)
            await route.bind(ips="*", port=port)
            outs.append(await async_wrap_errors(self.add_listener(proto, route)))

        return strip_none(outs)

    async def listen_loopback(self, proto, port, nic):
        """
        Listen on the loopback address for each address family supported by nic.

        "localhost" is translated to the correct AF-specific address by
        the bind_magic helper.
        """
        outs = []
        for af in nic.supported():
            route = nic.route(af)
            await route.bind(ips="localhost", port=port)
            outs.append(await async_wrap_errors(self.add_listener(proto, route)))

        return strip_none(outs)

    async def listen_local(
        self, proto, port, nic, limit=1
    ):
        """
        Listen on LAN-accessible addresses only.

        For IPv4 this means the private NIC address.  For IPv6 this means
        link-local addresses.  A limit on the number of binds per AF can
        be applied (default 1).

        Note: IPv4 LAN restriction without a firewall is inherently imperfect;
        a future enhancement could add basic firewall rules.
        """
        outs = []
        # When port=0 the OS assigns a free port.  Track the first assigned
        # port so all subsequent AF binds within this call land on the same
        # port number (consistent with what make_node_addr will advertise).
        effective_port = port
        for af in nic.supported():
            total = 0

            # Supports private IPv4 addresses.
            if af == IP4:
                nic_iprs = []
                for route in nic.rp[af]:
                    # For every local address in the route table.
                    for nic_ipr in route.nic_ips:
                        # Only bind to unique addresses.
                        if nic_ipr in nic_iprs:
                            continue
                        else:
                            nic_iprs.append(nic_ipr)
                            total += 1

                        # Avoid bind limit.
                        if limit is not None:
                            if total > limit:
                                break

                        # Don't modify the route table directly.
                        # Note: only binds to first IP.
                        # An IPR could represent a range.
                        local = copy.deepcopy(route)
                        ips = ipr_norm(nic_ipr)
                        await local.bind(ips=ips, port=effective_port)

                        # Save add output.
                        result = await async_wrap_errors(self.add_listener(proto, local))
                        outs.append(result)
                        # Port-0 readback: latch the OS-assigned port so all
                        # subsequent binds in this call use the same number.
                        if not effective_port and result:
                            effective_port = result[0]

            # Supports link-locals and unique local addresses.
            if af == IP6:
                route = nic.route(af)
                for link_local in route.link_locals:
                    total += 1

                    # Avoid bind limit.
                    if limit is not None:
                        if total > limit:
                            break

                    # Bind to link local.
                    local = nic.route(af)
                    ips = ipr_norm(link_local)
                    await async_wrap_errors(local.bind(ips=ips, port=effective_port))

                    # Save listener output.
                    result = await async_wrap_errors(self.add_listener(proto, local))
                    outs.append(result)
                    if not effective_port and result:
                        effective_port = result[0]

        return strip_none(outs)

    def add_msg_cb(self, msg_cb):
        """
        Register msg_cb on every server pipe managed by this daemon.

        Returns the scheduled task so callers that need the handler to be
        registered before the first message arrives can await it.
        Callers that don't require that ordering can ignore the return value.
        """

        async def func(server):
            server.add_msg_cb(msg_cb)

        # Return the task so callers that need to guarantee the handler is
        # registered before processing begins can do: await daemon.add_msg_cb(h)
        # Callers that don't care can ignore the return value as before.
        # Background: create_task schedules registration for a future event-loop
        # tick.  Any messages that arrive before that tick are delivered without
        # the handler, causing a silent miss.
        return asyncio.create_task(for_server_in_daemon(self, func))

    async def close(self):
        """Close all server pipes managed by this daemon."""
        async def func(server):
            """Attempt to close a single server pipe, ignoring OS and timeout errors."""
            try:
                await server.close()
            except (OSError, asyncio.TimeoutError):
                pass

        await for_server_in_daemon(self, func)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()
        return False


async def daemon_rewrite_workspace():
    """Development scratch function for testing daemon listen_local on a hard-coded interface."""
    nic = await Interface("wlx00c0cab5760d")
    async with Daemon() as serv:
        await serv.listen_local(TCP, 1337, nic)
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    async_test(daemon_rewrite_workspace)
