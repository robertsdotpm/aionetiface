"""Infrastructure server lists (STUN, PnP, etc.)."""
import hashlib
import json
import operator
import os
import random
from functools import reduce
from typing import Any, Dict, List

from .net.net_defs import IP4, UDP
from .utility.utils import rand_b, to_b

__all__ = ["INFRA", "INFRA_SEED", "rng_for_attempt", "filter_by_score", "get_infra"]

_SERVERS_JSON = os.path.join(os.path.dirname(__file__), "servers.json")

with open(_SERVERS_JSON, encoding="utf-8") as _f:
    INFRA_BUF = _f.read()

INFRA = json.loads(INFRA_BUF)
INFRA_SEED = rand_b(8)


def rng_for_attempt(attempt: int) -> random.Random:
    """Return a seeded Random instance deterministic for the given attempt number."""
    h = hashlib.sha256(INFRA_SEED + to_b(str(attempt))).digest()
    seed = int.from_bytes(h[:8], "big")
    return random.Random(seed)


def filter_by_score(
    groups: List[List[Dict[str, Any]]], threshold: float = 0.8
) -> List[List[Dict[str, Any]]]:
    """Return only those server groups whose minimum score meets or exceeds the threshold."""
    filtered = []
    for group in groups:
        if not group:
            continue
        min_score = min(item.get("score", 0) for item in group)
        if min_score >= threshold:
            filtered.append(group)
    return filtered


def get_infra(
    af: int, proto: int, name: str, no: int = 1, attempt: int = 0, sample: bool = False
) -> List[Any]:
    """Look up infrastructure server entries by address family, protocol, and name."""
    af_str = ".IPv4" if af == IP4 else ".IPv6"
    proto_str = ".UDP" if proto == UDP else ".TCP"
    name = name + af_str + proto_str
    parent = reduce(operator.getitem, name.split("."), INFRA)
    parent = filter_by_score(parent, threshold=0.8)
    rng = rng_for_attempt(attempt)
    if sample:
        return rng.sample(parent, min(no, len(parent)))
    parent = list(parent)
    rng.shuffle(parent)
    return parent[:no]
