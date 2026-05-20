# aionetiface

**Networking that actually knows where it is.**

`asyncio` was built for a world where every machine has one interface, one IP, and one path to the internet. aionetiface is for the world that actually exists — laptops with Wi-Fi and a USB tether, servers with two ISPs, phones on cellular and a VPN, hosts behind two layers of NAT. It is an async networking library for Python 3.5+ that treats *which interface*, *which address family*, and *which external IP* as first-class arguments to every socket you open.

```python
from aionetiface import *

nic = await Interface()                 # the OS's default interface…
route = await nic.route(IP6).bind()     # …its first IPv6 route…
pipe = await Pipe(TCP, ("example.com", 80), route).connect()
await pipe.send(b"GET / HTTP/1.0\r\n\r\n")
print(await pipe.recv(timeout=3))
await pipe.close()
```

That's a TCP client. Make it a UDP server by changing two arguments. Make it IPv4 by swapping `IP6` for `IP4`. The API doesn't fork.

---

## Why this exists

`socket.bind(("0.0.0.0", port))` is a lie. It binds to whatever the kernel feels like routing through, and your code has no idea which interface that was, what external address the world sees, or what NAT is in front of it. For a lot of programs that's fine. For VPNs, P2P apps, multi-homed servers, STUN/TURN clients, torrent clients, anything that wants to *load-balance across links* — it's a wall.

aionetiface walks that wall down:

- **External addresses are discoverable.** Every interface knows its public IPv4 and IPv6, per route, automatically (STUN under the hood). No more "what's my WAN IP" hardcoded HTTP calls.
- **Routes are objects you pass around.** A `Route` is the binding `(NIC IP → external IP)`. You hand one to `Pipe`, and the socket is bound exactly where you said.
- **One API for TCP / UDP / IPv4 / IPv6 / client / server.** A `Pipe` is a `Pipe`.
- **Python 3.5 still works.** The library back-ports newer asyncio fixes so old interpreters get modern behaviour.
- **Cross-platform.** Windows (XP through 11), Linux, macOS, FreeBSD, GhostBSD, Android.

---

## Install

```sh
python3 -m pip install aionetiface
```

On Python 3.5 specifically, bypass `setuptools>=68` (which needs 3.8+ syntax):

```sh
pip install wheel "setuptools<50"
pip install --no-build-isolation --no-deps -e .
```

---

## The async REPL

aionetiface ships its own asyncio REPL with top-level `await` working all the way back to Python 3.5:

```sh
$ python3 -m aionetiface
aionetiface 0.0.21 REPL on Python 3.8 / linux
Loop = selector, Process = spawn
Use "await" directly instead of "asyncio.run()".
>>> from aionetiface import *
>>> nic = await Interface()
>>> nic.rp[IP4][0].ext_ips
[IPRange('203.0.113.42')]
```

On 3.5–3.7 it wraps `await`-containing input in an `async def`, runs it on the loop, and merges new locals back in. You get the 3.8+ experience three versions early.

---

## The good parts

### Discover every interface, with external addresses attached

```python
from aionetiface import *

async def show():
    names = await list_interfaces()
    nics  = await load_interfaces(names, Interface)
    for nic in nics:
        for af in nic.supported():        # IP4, IP6, or both
            for route in nic.rp[af]:
                print("{0:>16}  {1} → ext {2}".format(
                    nic.name, route.nic_ips, route.ext_ips))

async_test(show)
```

Every `Route` is the pairing of *NIC-assigned addresses* and *what the world sees coming back*. For an unNATted IPv6 NIC the two sets are equal. For a NATted IPv4 link they aren't — and now you know.

### NAT classification on demand

```python
async def show_nat():
    nic = await Interface()
    await nic.load_nat()    # uses STUN's RFC3489 algorithm
    print(nic.nat)          # {"type": ..., "delta": {...}, ...}

async_test(show_nat)
```

Open / restricted / port-restricted / symmetric, with mapping-delta classification — the same data a TURN/STUN stack needs to decide whether hole-punching has a chance.

### One Pipe API — TCP, UDP, v4, v6, client, server

A TCP echo round-trip in 8 lines:

```python
async def msg_cb(msg, client_tup, pipe):
    await pipe.send(msg, client_tup)

async def example():
    server = await Pipe(TCP).connect(msg_cb=msg_cb)
    dest   = server.sock.getsockname()[0:2]
    client = await Pipe(TCP, dest).connect()
    await client.send(b"hello")
    assert b"hello" == await client.recv()
    await client.close(); await server.close()

async_test(example)
```

Change `TCP` to `UDP` and the code still works. Want to `await pipe.recv()` instead of registering a callback? Both styles coexist on the same pipe.

### STUN — the easy way

```python
async def wan():
    nic = await Interface()
    af  = nic.supported()[0]
    stun = STUNClient(af, ("stun.l.google.com", 19302), nic, proto=UDP)
    print(await stun.get_wan_ip())
    print(await stun.get_mapping())

async_test(wan)
```

Or get a vetted pool of working STUN servers in one call:

```python
clients = await get_stun_clients(IP4, n=3, nic=nic)
```

Each one is pre-probed — they answered a real mapping request before being handed back.

### Two-way pipe relays in one line

```python
pipe_a.add_pipe(pipe_b)
pipe_b.add_pipe(pipe_a)
```

Everything received on `pipe_a` is forwarded down `pipe_b` and vice versa. The aionetiface REST API uses exactly this trick to splice an active HTTP request into a long-running P2P connection.

### REST servers as decorators

```python
class API(RESTD):
    @RESTD.GET()
    async def index(self, v, pipe):
        return "hello"   # text/html

    @RESTD.POST(["proxies"], ["toxics"])
    async def add_toxic(self, v, pipe):
        # matches /proxies/<X>/toxics/<Y>;  v["proxies"] = X, v["toxics"] = Y
        return {"status": "ok"}   # JSON

    @RESTD.DELETE(["proxies"], ["toxics"])
    async def del_toxic(self, v, pipe):
        return b""   # application/octet-stream

async def serve():
    nic = await Interface()
    await API().listen_loopback(TCP, 60322, nic)

async_test(serve)
```

Path segments in brackets become named captures. Return type chooses the content-type. CORS and HTTP parsing are handled by `rest_service()` under the hood.

### Daemons that listen everywhere at once

```python
class EchoServer(Daemon):
    async def msg_cb(self, msg, client_tup, pipe):
        await pipe.send(msg, client_tup)

async def run():
    nic = await Interface()
    server = EchoServer()
    await server.listen_all(TCP, 20000, nic)   # every routable address
    await server.listen_all(UDP, 20000, nic)
    # …or .listen_loopback / .listen_local for scoped surfaces

async_test(run)
```

`listen_all` binds across every NIC IP and address family the interface supports. `listen_local` restricts to link-local / private. `listen_loopback` is for tools that should never leave the machine.

---

## Compatibility

| | |
|---|---|
| **Python** | 3.5 → 3.13 |
| **OS** | Windows XP – 11, Server 2003 – 2025, Linux, macOS, FreeBSD, GhostBSD, Android |
| **Event loops** | Selector, `CustomEventLoop` (default), uvloop. Proactor is *not* used — UDP on Windows goes through a polled-datagram transport, and subprocess calls fall back to a thread executor, so Selector-class loops work everywhere. |
| **Multiprocessing** | `spawn` on every platform, set automatically. No inherited sockets, no Windows surprises. |

`requires-python = ">=3.5"` is intentional, not aspirational — the back-ports and shims exist precisely so old interpreters get the same behaviour as new ones.

---

## Project

aionetiface is the networking foundation under the [Warpgate](https://www.warpgate.io/) NAT-traversal stack. Docs live at <https://aionetiface.readthedocs.io/>. Examples in [`docs/examples/`](docs/examples/) are runnable end-to-end.

Public domain. Pull requests welcome.
