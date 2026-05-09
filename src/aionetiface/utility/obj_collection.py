"""Concurrent object-collection and first-result helpers."""
import inspect
import asyncio
import random
from .utils import strip_none
from ..net.net_defs import IP4, UDP
from ..servers import get_infra
from ..nic.interface import Interface
from ..protocol.stun.stun_defs import RFC3489, RFC5389
from ..protocol.stun.stun_client import STUNClient


# Given a list and a random str.
# Return a deterministically shuffled generator.
def seed_iter(items, seed_str):
    """Yield items in a deterministically shuffled order seeded by seed_str."""
    # avoid mutating the original list
    items_copy = list(items)

    # deterministic RNG based on string
    rng = random.Random(seed_str)
    rng.shuffle(items_copy)

    # Return generator.
    for item in items_copy:
        yield item


# Given a func that takes a list of named params and a dict
# of mixed kv pairs -- only use the kvs that match a param.
def func_relevant_params(func, kv):
    """Return only the key-value pairs from kv that match func's parameter names."""
    sig = inspect.signature(func)
    params = sig.parameters
    param_names = list(params.keys())
    relevant_params = {k: kv[k] for k in param_names if k in kv}
    return relevant_params


class ObjCollection:
    """Factory-based collection that builds and qualifies groups of objects concurrently."""
    def __init__(
        self,
        obj_factory,
        select_servers=None,
    ):
        self.obj_factory = obj_factory
        self.select_servers = select_servers

    # Get n new objs using obj factory.
    # An optional function can be provided to select the server.
    async def get_n(self, n, kv=None):
        if kv is None:
            kv = {}
        # If func is defined for getting dest server
        # build a list of servers to use for connection.
        if self.select_servers:
            servers = self.select_servers(n, kv)
        else:
            servers = [None] * n  # fixed from None * n

        # Ensure servers list is at least length n
        if len(servers) < n:
            servers += [None] * (n - len(servers))

        # Construct fresh list of objects.
        objs = [self.obj_factory(kv["factory"], dest=servers[i]) for i in range(0, n)]

        # Run objects await methods if awaitable.
        await asyncio.gather(
            *[o for o in objs if inspect.isawaitable(o)], return_exceptions=True
        )

        return objs

    # Get n new objects but add a function to qualify them.
    # Qualify function returns the obj if it passes.
    async def get_n_qualify(
        self,
        n,
        kv,
        qualify,
        min_success=None,
        max_attempts=2,
    ):
        out = []
        attempts = 0
        min_success = min_success or n
        while attempts < max_attempts:
            needed = min_success - len(out)
            if needed <= 0:
                break

            # Fetch the needed objects and run qualify on each
            out += strip_none(
                await asyncio.gather(
                    *[qualify(o) for o in (await self.get_n(needed, kv))],
                    return_exceptions=True,
                )
            )

            attempts += 1
            if len(out) >= min_success:
                break

        return out[:min_success]


async def workspace_one():
    def select_servers(n, kv):
        """Return a list of n (ip, port) tuples for the STUN server matching kv['mode']."""
        if kv["mode"] == RFC3489:
            name = "STUN(test_nat)"

        if kv["mode"] == RFC5389:
            name = "STUN(see_ip)"

        servers = get_infra(kv["af"], kv["proto"], name, no=n)

        return [(s[0]["ip"], s[0]["port"]) for s in servers]

    async def qualify(obj):
        out = await obj.get_mapping()
        if out:
            return obj

    c = ObjCollection(
        lambda kparams, dest=None: STUNClient(**kparams, dest=dest),
        select_servers=select_servers,
    )

    out = await c.get_n_qualify(
        5,
        {
            "af": IP4,
            "nic": Interface("default"),
            "mode": RFC3489,
            "proto": UDP,
        },
        qualify,
    )

    print(out)
