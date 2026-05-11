"""Low-level utilities: numeric, list, dict, range, and miscellaneous helpers.

This module also re-exports the focused helpers from :mod:`type_conv`,
:mod:`hashing`, and :mod:`async_helpers` so existing callers continue to work.
"""
import asyncio
import copy
import hashlib
import inspect
import ipaddress
import itertools
import os
import platform
import random
import re
import sys
import time
import traceback
import urllib.parse
try:
    pass
except ImportError:
    # typing.Type was added in Python 3.5.3; fall back to Any for older builds.
    Type = Any  # type: ignore
from ecdsa.curves import NIST192p
import ecdsa

from .fstr import fstr
from .error_logger import log, log_exception, log_p2p

# Re-exported submodules.
from .type_conv import (  # noqa: F401
    to_b,
    to_s,
    to_hs,
    to_h,
    to_i,
    to_n,
    i_to_b,
    b_to_i,
    h_to_b,
)
from .hashing import (  # noqa: F401
    sha256,
    hash160,
    sha3_256,
    b_sha3_256,
    dhash,
    rendezvous_score,
)
from .async_helpers import (  # noqa: F401
    create_task,
    get_running_loop,
    safe_run,
    return_true,
    threshold_gather,
    async_wrap_errors,
    sync_wrap_errors,
    async_retry,
    async_test,
    async_to_sync,
    handler_done_builder,
    run_handler,
    run_handlers,
    run_in_executor,
    run_in_executor2,
    safe_gather,
    sleep_random,
)

__all__ = [
    "vmaj",
    "vmin",
    "DB_READ_LOCK",
    "DB_WRITE_LOCK",
    "STATUS_RETRY",
    "STATUS_SUCCESS",
    "STATUS_FAILURE",
    "MAX_PORT",
    "to_b",
    "to_s",
    "to_hs",
    "to_h",
    "to_i",
    "to_n",
    "i_to_b",
    "b_to_i",
    "h_to_b",
    "ip_f",
    "rm_whitespace",
    "urlencode",
    "urldecode",
    "sha256",
    "hash160",
    "sha3_256",
    "b_sha3_256",
    "dhash",
    "rendezvous_score",
    "valid_port",
    "port_wrap",
    "to_unique",
    "strip_none",
    "shuffle",
    "d_keys",
    "d_vals",
    "list_join",
    "list_x_to_dict",
    "from_range",
    "in_range",
    "len_range",
    "dict_plus",
    "b_and",
    "b_or",
    "is_number",
    "is_bytes",
    "class_name",
    "timestamp",
    "bind_str",
    "rand_rang",
    "get_bits",
    "neg_flip",
    "numeric_distance",
    "n_dist",
    "rand_rang_alias",
    "rand_b",
    "rand_b_readable",
    "rand_plain",
    "list_clone_rand",
    "list_exclude_dict",
    "list_get_dict",
    "file_get_contents",
    "to_type",
    "dict_child",
    "dict_merge",
    "xor_bufs",
    "bits_to_bytes",
    "buf_in_class",
    "hamming_weight",
    "range_intersects",
    "intersect_range",
    "field_wrap",
    "field_dist",
    "sorted_search",
    "create_task",
    "get_running_loop",
    "safe_run",
    "return_true",
    "threshold_gather",
    "async_wrap_errors",
    "sync_wrap_errors",
    "async_retry",
    "async_test",
    "async_to_sync",
    "handler_done_builder",
    "run_handler",
    "run_handlers",
    "run_in_executor",
    "run_in_executor2",
    "safe_gather",
    "sleep_random",
    "recover_verify_key",
    "find_intersect",
    "as_slice",
    "is_ascii",
    "sqlite_dict_factory",
    "what_exception",
    "my_except_hook",
    "ensure_resolved",
    "fstr",
    "log",
    "log_exception",
    "log_p2p",
    "cancel_task",
    "cancel_tasks",
    "rm_done_tasks",
    "gather_or_cancel",
    "handle_exceptions",
    "os_id",
]


# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------

vmaj, vmin, _ = platform.python_version_tuple()
vmaj = int(vmaj)
vmin = int(vmin)

if vmaj < 3 or (vmaj == 3 and vmin < 5):
    raise RuntimeError("aionetiface requires Python 3.5 or higher.")


# ---------------------------------------------------------------------------
# asyncio compatibility shim for Python < 3.7
# ---------------------------------------------------------------------------

if not hasattr(asyncio, "create_task"):
    log("No create_task found; falling back to ensure_future.")
    asyncio.create_task = asyncio.ensure_future


# ---------------------------------------------------------------------------
# Status codes
# ---------------------------------------------------------------------------

DB_READ_LOCK = 0
DB_WRITE_LOCK = 1
STATUS_RETRY = 1
STATUS_SUCCESS = 2
STATUS_FAILURE = 3
MAX_PORT = 65535


# ---------------------------------------------------------------------------
# Miscellaneous helpers kept here (string / list / dict / numeric / binary)
# ---------------------------------------------------------------------------


# IP address helper.
ip_f = ipaddress.ip_address

# Regex / string helpers.
def re_unescape(x):
    """Remove backslash escapes from a string."""
    return re.sub(r"\\(.)", r"\1", x)


def rm_whitespace(x):
    """Remove all whitespace from string x."""
    return re.sub(r"\s+", "", x, flags=re.UNICODE)


def urlencode(x):
    """Percent-encode a string for use in a URL."""
    return to_b(urllib.parse.quote(x))


def urldecode(x):
    """Decode a percent-encoded URL component."""
    return to_b(urllib.parse.unquote(x))


# Port helpers.
def valid_port(p):
    """Return True if p is a valid TCP/UDP port number (1-65535)."""
    return 1 <= p <= MAX_PORT


def port_wrap(p):
    """Wrap p into the valid port range, skipping privileged ports."""
    return (p % MAX_PORT) or 1


# List / dict helpers.
def to_unique(x):
    """Return a list with duplicates removed (preserving first occurrence)."""
    return [i for n, i in enumerate(x) if i not in x[:n]]


def strip_none(x):
    """Remove None values from a list."""
    return [i for i in x if i is not None]


def shuffle(x):
    """Shuffle x in place and return it."""
    random.shuffle(x)
    return x


def d_keys(x):
    """Return the keys of dict d as a list."""
    return list(x.keys())


def d_vals(x):
    """Return the values of dict d as a list."""
    return list(x.values())


def list_join(lists):
    """Concatenate a list of lists into a flat list."""
    return list(itertools.chain.from_iterable(lists))


def list_x_to_dict(x):
    """Call .dict() on each element of x and return the resulting list."""
    return [v.dict() for v in x]


# Numeric / range helpers.
def from_range(r):
    """Return a value clamped into [lo, hi]."""
    return random.randrange(r[0], r[1] + 1)


def in_range(x, r):
    """Return True if lo <= val <= hi."""
    return r[0] <= x <= r[1]


def len_range(r):
    """Return the length of range r as r[1] - r[0]."""
    return r[1] - r[0]


def dict_plus(d, k):
    """Return d[k] if k exists, else 0."""
    return d[k] if k in d else 0


# Byte-level bitwise operations.
def b_and(a, b):
    """Bitwise AND of two equal-length byte strings."""
    return bytes(map(lambda x, y: x & y, a, b))


def b_or(a, b):
    """Bitwise OR of two equal-length byte strings."""
    return bytes(map(lambda x, y: x | y, a, b))


# Type predicates.
def is_number(x):
    """Return True if x can be interpreted as a number."""
    return to_s(x).isnumeric()


def is_bytes(x):
    """Return True if x is a bytes-like object."""
    return isinstance(x, bytes)


# Reflection helpers.
def class_name(x):
    """Return the class name of obj as a string."""
    return type(x).__name__ if inspect.isclass(x) else None


def timestamp(precise=False):
    """Return the current time as an integer (or float when precise=True)."""
    return time.time() if precise else int(time.time())


# Address string helpers.
def bind_str(r):
    """Format an (ip, port) tuple as a 'ip:port' string."""
    return fstr(
        "{0}:{1}",
        (
            r.bind_tup()[0],
            r.bind_tup()[1],
        ),
    )

# Convenience aliases.
rand_rang = random.randrange


# ---------------------------------------------------------------------------
# Bit manipulation
# ---------------------------------------------------------------------------


def get_bits(n, length, position=0):
    """
    Extract `length` bits from integer `n` starting at `position`
    (0 = least significant bit).

    Example: get_bits(0b11010, 3, 1) -> 0b101 (bits 1..3)
    """
    mask = (1 << length) - 1
    return mask & (n >> position)


# ---------------------------------------------------------------------------
# Numeric distance helpers
# ---------------------------------------------------------------------------


def neg_flip(result, x, y):
    """Return -result if x > y, otherwise result."""
    return -result if x > y else result


def numeric_distance(x, y):
    """Signed distance between two numbers: positive if y > x."""
    raw = max(x, y) - min(x, y)
    return neg_flip(raw, x, y)


# Short alias kept for backward compatibility.
n_dist = numeric_distance


# ---------------------------------------------------------------------------
# Randomness helpers
# ---------------------------------------------------------------------------


def rand_rang_alias():
    """Alias kept for backward compatibility. Prefer random.randrange directly."""
    return random.randrange


def rand_b(n):
    """Return n random bytes from the OS entropy source."""
    return os.urandom(n)


def rand_b_readable(n):
    """Return n random printable ASCII bytes (letters, digits, space)."""
    chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    return bytes(random.choice(chars) for _ in range(n))


def rand_plain(n):
    """Return n random alphanumeric bytes (no spaces)."""
    charset = b"012345678abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return bytes(random.choice(charset) for _ in range(n))


def list_clone_rand(the_list, n):
    """Return a randomly shuffled copy of the_list, trimmed to n elements."""
    the_clone = the_list[:]
    random.shuffle(the_clone)
    return the_clone[:n]


# ---------------------------------------------------------------------------
# List / dict utilities
# ---------------------------------------------------------------------------


def list_exclude_dict(
    key_name, exclusion, entry_list
):
    """Return entry_list without entries where entry[key_name] == exclusion."""
    result = []
    for entry in entry_list:
        if key_name not in entry:
            result.append(entry)
            continue

        if entry[key_name] != exclusion:
            result.append(entry)

    return result


def list_get_dict(
    key_name, criteria, entry_list
):
    """Return the first entry in entry_list where entry[key_name] == criteria."""
    for entry in entry_list:
        if key_name not in entry:
            continue

        if entry[key_name] == criteria:
            return entry

    return None


def file_get_contents(path):
    """Read and return the raw bytes of the file at path."""
    with open(path, mode="rb") as f:
        return f.read()


def to_type(x, out_type):
    """Convert x to the same type as out_type (str or bytes)."""
    if isinstance(out_type, str):
        return to_s(x)
    return to_b(x)


def dict_child(x, y):
    """
    Merge child dict x into template dict y.

    Returns a deep copy of y with any matching keys overwritten by x.
    y is the template (larger); x provides the overrides (smaller).
    """
    if len(x) > len(y):
        log(
            "dict_child: x has more keys than y - are the arguments in the right order?"
        )

    out = copy.deepcopy(y)
    for key in x:
        out[key] = x[key]
    return out


def dict_merge(x, y):
    """Merge dict y into dict x in place and return x."""
    x.update(y)
    return x


# ---------------------------------------------------------------------------
# Binary utilities
# ---------------------------------------------------------------------------


def xor_bufs(a, b):
    """
    XOR two byte strings together.

    Cycles through each buffer by index, then clips to the shorter length.
    """
    a = bytearray(a)
    b = bytearray(b)
    a_len = len(a)
    b_len = len(b)

    result = bytearray()
    for i in range(max(a_len, b_len)):
        result.append(a[i % a_len] ^ b[i % b_len])

    return bytes(result)[: min(a_len, b_len)]


def bits_to_bytes(s):
    """Convert a binary string like '1010' to bytes."""
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder="big")


def buf_in_class(cls, buf):
    """
    Search cls for a member whose value equals buf.

    Returns the member name if found, False otherwise.
    """
    for member in dir(cls):
        val = getattr(cls, member)
        if not isinstance(val, type(buf)):
            continue
        if val == buf:
            return member
    return False


def hamming_weight(n):
    """
    Count the number of set bits in integer n (also called popcount).

    Uses Kernighan's method: each iteration clears the lowest set bit.

    Reference: https://stackoverflow.com/questions/843828
    """
    count = 0
    while n:
        count += 1
        n &= n - 1
    return count


# ---------------------------------------------------------------------------
# Range utilities
# ---------------------------------------------------------------------------


def range_intersects(a, b):
    """
    Return True if two numeric ranges [a[0], a[1]] and [b[0], b[1]] overlap.

    The algorithm sorts the two ranges as pairs so the lower-starting range
    comes first, then flattens to [lo_start, lo_end, hi_start, hi_end].
    The ranges overlap when hi_start <= lo_end.
    """
    if a == b:
        return True

    # Sort ranges as pairs (not all 4 elements) so the pair with the smaller
    # start value is first, giving [lo_start, lo_end, hi_start, hi_end].
    ordered = sum(sorted([a, b]), [])
    return ordered[2] <= ordered[1]


def intersect_range(a, b):
    """
    Return the overlapping sub-range [start, end] of ranges a and b.

    Sorts all four endpoints together; the two middle values are the
    boundaries of the intersection in ascending order.
    """
    all_endpoints = sorted(a + b)
    return [all_endpoints[1], all_endpoints[2]]


def field_wrap(n, field):
    """
    Wrap integer n so that it falls within [field[0], field[1]].
    """
    start_range, stop_range = field
    return start_range + (n % (stop_range - start_range + 1))


def field_dist(x, y, field):
    """
    Return the shortest signed distance between x and y within a circular field.

    A negative result means travelling from y to x is shorter going backwards.
    field is the total size of the circular space (e.g. 65536 for port numbers).
    """
    max_no = max(x, y)
    min_no = min(x, y)
    dist = max_no - min_no

    if not dist:
        return 0

    # Direct distance vs. wrap-around distance.
    wrap_dist = min_no + (field - max_no)
    ret = min(dist, wrap_dist)

    return -ret if x == min_no else ret


# ---------------------------------------------------------------------------
# Sorted binary search
# ---------------------------------------------------------------------------


def sorted_search(
    n_list, target, start_at=None
):
    """
    Binary search returning the index of the first element >= target.

    Assumes n_list is sorted in ascending order. Returns None if the list
    is empty, 0 if target is smaller than all elements.

    start_at: optional starting index (defaults to the middle of the list).
    """
    list_len = len(n_list)
    if not list_len:
        return None

    if start_at is None:
        index = list_len // 2
    else:
        index = start_at % list_len

    for iteration in range(list_len):
        if index <= 0:
            return 0

        if n_list[index] >= target:
            if n_list[index - 1] < target:
                return index
            index -= int(index / 2) or 1
        else:
            index += int(index / 2) or 1

        if index >= list_len - 1:
            return list_len - 1

    raise ValueError("sorted_search: list may not be sorted.")


# ---------------------------------------------------------------------------
# Cleanup re-exports (late import to avoid cycles)
# ---------------------------------------------------------------------------

from .cleanup import (  # noqa: E402  # pylint: disable=cyclic-import
    cancel_task,
    cancel_tasks,
    rm_done_tasks,
    gather_or_cancel,
    handle_exceptions,
)


# ---------------------------------------------------------------------------
# Cryptography utilities
# ---------------------------------------------------------------------------


def recover_verify_key(
    msg_b,
    sig_b,
    vk_b=None,
    curve=NIST192p,
    hashfunc=hashlib.sha1,
):
    """
    Recover ECDSA verify key(s) from a signature.

    If vk_b is provided, raises if that key is not among the recovered keys.
    Returns the first recovered key that successfully verifies the signature.
    """
    vk_list = ecdsa.VerifyingKey.from_public_key_recovery(
        signature=sig_b, data=msg_b, curve=curve, hashfunc=hashfunc
    )

    if vk_b is not None:
        if not any(vk.to_string("compressed") == vk_b for vk in vk_list):
            raise ValueError(
                "recover_verify_key: expected key not found in recovered set."
            )

    for vk in vk_list:
        try:
            vk.verify(sig_b, msg_b)
            return vk
        except ecdsa.BadSignatureError:
            continue

    raise ValueError("recover_verify_key: no recovered key could verify the signature.")


# ---------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------


def find_intersect(list_a, list_b):
    """Yield values that appear in both list_a and list_b."""
    for a_val in list_a:
        for b_val in list_b:
            if a_val == b_val:
                yield a_val


def as_slice(needle, haystack):
    """Return a slice for the first occurrence of needle in haystack, or None."""
    pos = haystack.find(needle)
    if pos == -1:
        return None
    return slice(pos, pos + len(needle))


def is_ascii(data):
    """Return True if data can be encoded/decoded as ASCII without errors."""
    if isinstance(data, bytes):
        try:
            data.decode("ascii")
            return True
        except UnicodeDecodeError:
            return False
    else:
        try:
            data.encode("ascii")
            return True
        except UnicodeEncodeError:
            return False


def sqlite_dict_factory(cursor, row):
    """Row factory for sqlite3 that returns rows as dicts keyed by column name."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def what_exception():
    """
    Print a formatted summary of the current exception to stdout.

    Intended for debugging. Includes exception type, source file, line number,
    and full traceback.
    """
    exc_type, exc_val, exc_tb = sys.exc_info()

    fname = "Unknown"
    lineno = 0

    if exc_tb is not None:
        curr_tb = exc_tb
        while curr_tb.tb_next:
            curr_tb = curr_tb.tb_next

        try:
            if hasattr(curr_tb, "tb_frame") and curr_tb.tb_frame:
                filename = curr_tb.tb_frame.f_code.co_filename
                fname = os.path.split(filename)[1]
            lineno = curr_tb.tb_lineno
        except AttributeError:
            pass

    print("--- Exception Detected ---")
    print("Type: {0}".format(exc_type.__name__ if exc_type else "None"))
    print("File: {0}".format(fname))
    print("Line: {0}".format(lineno))
    print("\nFull Traceback:")
    print(traceback.format_exc())


def my_except_hook(exctype, value, tb):
    """Global exception hook that logs unexpected top-level exceptions."""
    log("Global except handler called.")
    log_exception()


def ensure_resolved(targets):
    """
    Assert that all targets have been resolved (i.e. target.resolved is truthy).

    Raises with a descriptive message identifying which target failed.
    """
    if not isinstance(targets, list):
        targets = [targets]

    for i, target in enumerate(targets):
        if not target.resolved:
            raise ValueError(
                "Target offset={}, id={}, type={} not resolved".format(
                    i, id(target), type(target)
                )
            )


# ---------------------------------------------------------------------------
# Self-test (run directly with: python utils.py)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# OS identification for the wire-format peer-OS field
# ---------------------------------------------------------------------------

def os_id():
    """Return the local OS identifier, taken straight from the platform module.

    The shape is ``platform.system() + "-" + platform.release()``, e.g.
    ``Windows-XP``, ``Windows-10``, ``Linux-5.10.0``, ``Darwin-22.1.0``,
    ``FreeBSD-13.2-RELEASE``. No invented tokens -- whatever the platform
    module says, that's what we ship on the wire. Downstream consumers
    (tcp_punch port-pool selection, future per-OS tuning) substring-match
    against the values they care about (e.g. ``"XP" in os`` for the
    Windows XP narrow-ephemeral-pool case). Empty release falls back to
    just system().

    Any wire-format separator chars (``^``, ``|``, ``,``, ``{``, ``}``)
    that platform happens to emit are replaced with ``_`` so the value
    is always safe to embed in the addr serialisation.
    """
    sys_name = platform.system() or ""
    rel = platform.release() or ""
    if rel:
        raw = sys_name + "-" + rel
    else:
        raw = sys_name
    for sep in ("^", "|", ",", "{", "}"):
        raw = raw.replace(sep, "_")
    return raw


if __name__ == "__main__":  # pragma: no cover
    assert not range_intersects([1, 1], [2, 2])
    assert range_intersects([1, 2], [2, 2])
    assert range_intersects([1, 2], [1, 2])
    assert range_intersects([1, 10], [5, 20])
    print("os_id() ->", os_id())
    print("Self-tests passed.")
