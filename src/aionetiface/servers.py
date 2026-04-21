import hashlib
import json
import operator
import os
import random
from functools import reduce

from .net.net_defs import *

_SERVERS_JSON = os.path.join(os.path.dirname(__file__), "servers.json")

with open(_SERVERS_JSON) as _f:
    INFRA_BUF = _f.read()

INFRA = json.loads(INFRA_BUF)
INFRA_SEED = rand_b(8)


def rng_for_attempt(attempt):
    h = hashlib.sha256(INFRA_SEED + to_b(str(attempt))).digest()
    seed = int.from_bytes(h[:8], "big")
    return random.Random(seed)


def filter_by_score(groups, threshold=0.8):
    filtered = []
    for group in groups:
        if not group:
            continue
        min_score = min(item.get("score", 0) for item in group)
        if min_score >= threshold:
            filtered.append(group)
    return filtered


def get_infra(af, proto, name, no=1, attempt=0, sample=False):
    af_str = ".IPv4" if af == IP4 else ".IPv6"
    proto_str = ".UDP" if proto == UDP else ".TCP"
    name = name + af_str + proto_str
    parent = reduce(operator.getitem, name.split("."), INFRA)
    parent = filter_by_score(parent, threshold=0.8)
    rng = rng_for_attempt(attempt)
    if sample:
        return rng.sample(parent, min(no, len(parent)))
    else:
        parent = list(parent)
        rng.shuffle(parent)
        return parent[:no]
