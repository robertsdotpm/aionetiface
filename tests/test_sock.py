from aionetiface import *
from aionetiface import get_infra  # explicit -- not always re-exported by wildcard
from aionetiface.testing import AsyncTestCase


class TestSock(AsyncTestCase):
    async def test_reuse_port(self):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s1.bind(("", 0))
        # s1.connect(("www.google.com", 80))

        port = s1.getsockname()[1]
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s2.bind(("", port))
        # s2.connect(("www.google.com", 80))

        s1.close()
        s2.close()

    async def test_socket_factory_connect(self):
        loop = asyncio.get_event_loop()
        i = await Interface()
        af = i.supported()[0]
        # Pick several STUN-TCP servers from get_infra so one unreachable
        # host doesn't fail the socket-factory test. First one that opens
        # cleanly wins.
        try:
            groups = get_infra(IP4, TCP, "STUN(see_ip)", no=5)
        except Exception:
            groups = []
        hosts = []
        for group in groups:
            if not group:
                continue
            entry = group[0]
            fqn = (entry.get("fqns") or [entry.get("ip")])[0]
            if fqn:
                hosts.append((fqn, entry.get("port", 3478)))
        if not hosts:
            hosts = [("ovh1.p2pd.net", 3478)]

        last_err = None
        connected = False
        for host, port in hosts:
            r = await i.route(af).bind(0)
            try:
                dest = Address(host, port)
                await dest.res(r)
                dest = dest.select_ip(IP4)
                s = await socket_factory(route=r, dest_addr=dest, sock_type=TCP, conf=NET_CONF)
                con_task = asyncio.create_task(loop.sock_connect(s, dest.tup))
                await asyncio.wait_for(con_task, 2)
                connected = True
                if s is not None:
                    s.close()
                break
            except (OSError, ConnectionError, asyncio.TimeoutError, LookupError) as exc:
                last_err = exc
                continue

        if not connected:
            self.skipTest("No reachable STUN-TCP host (last error: {!r})".format(last_err))

    async def test_high_port_reuse(self):
        # Config for reuse.
        conf = copy.deepcopy(NET_CONF)
        conf["reuse_addr"] = True

        # Load default interface.
        i = await Interface()
        r = i.route()

        # Make a new socket bound to a high order port.
        high_sock, high_port = await get_high_port_socket(r, socket_factory)

        # Make a new socket that shares the same port.
        r = await i.route().bind(high_port)
        reuse_sock = await socket_factory(r, conf=conf)

        # Cleanup both socket handles.
        high_sock.close()
        reuse_sock.close()


if __name__ == "__main__":
    main()

"""
one of the nic ips is not working. why would this break the
stun code though?
"""
