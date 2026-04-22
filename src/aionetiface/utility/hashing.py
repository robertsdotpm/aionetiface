"""Hashing helpers: SHA-256, SHA3-256, rendezvous, deterministic hashing."""
import hashlib
import math
from typing import Any

from .fstr import fstr
from .type_conv import to_b, to_s, b_to_i


__all__ = [
    "sha256",
    "hash160",
    "sha3_256",
    "b_sha3_256",
    "dhash",
    "rendezvous_score",
]


def sha256(x: Any) -> str:
    """Return the SHA-256 hex digest of x."""
    return to_s(hashlib.sha256(to_b(x)).hexdigest())


def hash160(x: Any) -> str:
    """Return a 40-character hex digest of x using SHA-256 (truncated to 160 bits)."""
    return hashlib.sha256(to_b(x)).hexdigest()[:40]


def sha3_256(x: Any) -> str:
    """Return the SHA3-256 hex digest of x."""
    return to_s(hashlib.sha3_256(to_b(x)).hexdigest())


def b_sha3_256(x: Any) -> bytes:
    """Return the raw SHA3-256 digest bytes of x."""
    return hashlib.sha3_256(to_b(x)).digest()


# Deterministic hash: converts x to a string, hashes it, returns int.
def dhash(x: Any) -> int:
    """Return a deterministic integer hash of x via SHA-256."""
    return b_to_i(hashlib.sha256(to_b(fstr("{0}", (x,)))).digest())


def rendezvous_score(*tokens: bytes) -> float:
    """Highest-random-weight score for a server in rendezvous hashing.

    Hash all tokens concatenated with SHA-256 and map to an exponentially
    distributed score via -log(U).  Higher score = preferred server.
    Call once per (key, server) pair; rank servers by score descending.

    All tokens must be bytes - callers are responsible for converting ints,
    strings, etc. before calling (e.g. bytes([af]), to_b(host), ...).
    """
    digest = hashlib.sha256(b"".join(tokens)).digest()
    u = (int.from_bytes(digest, "big") + 1) / (2**256)
    return -math.log(u)
