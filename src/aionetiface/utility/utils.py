"""Low-level type-conversion, encoding, and timing utilities."""
import asyncio
import binascii
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Type,
    Union,
)
import copy
import functools
import hashlib
import inspect
import ipaddress
import itertools
import math
import os
import platform
import random
import re
import sys
import time
import traceback
import unittest
import urllib.parse
from ecdsa.curves import NIST192p
import ecdsa

from .fstr import fstr
from .error_logger import log, log_exception, log_p2p

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
]


# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------

vmaj, vmin, _ = platform.python_version_tuple()
vmaj = int(vmaj)
vmin = int(vmin)

if vmaj < 3:
    raise RuntimeError("Python 2 not supported.")

if vmin < 5:
    raise RuntimeError("Non-Windows OS needs Python 3.5 or higher")

if vmin < 8 and sys.platform == "win32":
    pass  # Windows 3.8+ preferred but not enforced for now


# ---------------------------------------------------------------------------
# asyncio compatibility shim for Python < 3.7
# ---------------------------------------------------------------------------

if not hasattr(asyncio, "create_task"):
    log("No create_task found; falling back to ensure_future.")
    asyncio.create_task = asyncio.ensure_future


# ---------------------------------------------------------------------------
# unittest compatibility shim for Python < 3.8
# ---------------------------------------------------------------------------

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    try:
        import aiounittest

        unittest.IsolatedAsyncioTestCase = aiounittest.AsyncTestCase

        def safe_run_patch(self):
            """Patch the test case's event loop so coroutines are wrapped with safe_run."""
            loop = asyncio.get_event_loop()
            run_wrap = loop.run_until_complete
            loop.run_until_complete = lambda f: run_wrap(safe_run(f))
            loop.set_debug(False)

        unittest.IsolatedAsyncioTestCase.get_event_loop = safe_run_patch
    except (ImportError, AttributeError):
        pass


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
# Type conversion helpers
# ---------------------------------------------------------------------------


def to_b(x: Union[str, bytes]) -> bytes:
    """Convert x to bytes. Passes through if already bytes."""
    return x if isinstance(x, bytes) else x.encode("ascii", errors="ignore")


def to_s(x: Union[str, bytes]) -> str:
    """Convert x to str. Passes through if already str."""
    return x if isinstance(x, str) else x.decode("utf-8", errors="ignore")


# Hex string conversions.
def to_hs(x: Any) -> str:
    """Convert bytes or str to a lowercase hex string."""
    return to_s(binascii.hexlify(to_b(x)))


def to_h(x: Any) -> str:
    """Convert x to hex, returning '00' for empty input."""
    return to_hs(x) if len(x) else "00"


# Integer / numeric conversions.
def to_i(x: Any) -> int:
    """Convert a hex string or int to an integer."""
    return x if isinstance(x, int) else int(x, 16)


def to_n(x: Any) -> int:
    """Convert a decimal string or int to an integer."""
    return x if isinstance(x, int) else int(to_s(x), 10)


# Integer <-> bytes conversions.
def i_to_b(x: int, o: str = "little") -> bytes:
    """Encode an integer as bytes in the given byte order."""
    return x.to_bytes((x.bit_length() + 7) // 8, o)


def b_to_i(x: bytes, o: str = "little") -> int:
    """Decode bytes to an integer in the given byte order."""
    return int.from_bytes(x, o)


def h_to_b(x: Any, o: str = "little") -> bytes:
    """Decode a hex string to bytes."""
    return binascii.unhexlify(to_b(x))


# IP address helper.
ip_f = ipaddress.ip_address

# Regex / string helpers.
def re_unescape(x: str) -> str:
    """Remove backslash escapes from a string."""
    return re.sub(r"\\(.)", r"\1", x)


def rm_whitespace(x: str) -> str:
    """Remove all whitespace from string x."""
    return re.sub(r"\s+", "", x, flags=re.UNICODE)


def urlencode(x: str) -> bytes:
    """Percent-encode a string for use in a URL."""
    return to_b(urllib.parse.quote(x))


def urldecode(x: str) -> bytes:
    """Decode a percent-encoded URL component."""
    return to_b(urllib.parse.unquote(x))


# Hash helpers.
def sha256(x: Any) -> str:
    """Return the SHA-256 hex digest of x."""
    return to_s(hashlib.sha256(to_b(x)).hexdigest())


def hash160(x):
    """Return a 40-character hex digest of x using SHA-256 (truncated to 160 bits)."""
    return hashlib.sha256(to_b(x)).hexdigest()[:40]


def sha3_256(x):
    """Return the SHA-256 hex digest of x."""
    return to_s(hashlib.sha256(to_b(x)).hexdigest())


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

    All tokens must be bytes — callers are responsible for converting ints,
    strings, etc. before calling (e.g. bytes([af]), to_b(host), ...).
    """
    digest = hashlib.sha256(b"".join(tokens)).digest()
    u = (int.from_bytes(digest, "big") + 1) / (2**256)
    return -math.log(u)


# Port helpers.
def valid_port(p: int) -> bool:
    """Return True if p is a valid TCP/UDP port number (1–65535)."""
    return 1 <= p <= MAX_PORT


def port_wrap(p: int) -> int:
    """Wrap p into the valid port range, skipping privileged ports."""
    return (p % MAX_PORT) or 1


# List / dict helpers.
def to_unique(x: list) -> list:
    """Return a list with duplicates removed (preserving first occurrence)."""
    return [i for n, i in enumerate(x) if i not in x[:n]]


def strip_none(x: list) -> list:
    """Remove None values from a list."""
    return [i for i in x if i is not None]


def shuffle(x: list) -> list:
    """Shuffle x in place and return it."""
    random.shuffle(x)
    return x


def d_keys(x: dict) -> list:
    """Return the keys of dict d as a list."""
    return list(x.keys())


def d_vals(x: dict) -> list:
    """Return the values of dict d as a list."""
    return list(x.values())


def list_join(lists: list) -> list:
    """Concatenate a list of lists into a flat list."""
    return list(itertools.chain.from_iterable(lists))


def list_x_to_dict(x: list) -> list:
    """Call .dict() on each element of x and return the resulting list."""
    return [v.dict() for v in x]


# Numeric / range helpers.
def from_range(r: Any) -> int:
    """Return a value clamped into [lo, hi]."""
    return random.randrange(r[0], r[1] + 1)


def in_range(x: Any, r: Any) -> bool:
    """Return True if lo <= val <= hi."""
    return r[0] <= x <= r[1]


def len_range(r: Any) -> int:
    """Return the length of range r as r[1] - r[0]."""
    return r[1] - r[0]


def dict_plus(d: dict, k: Any) -> Any:
    """Return d[k] if k exists, else 0."""
    return d[k] if k in d else 0


# Byte-level bitwise operations.
def b_and(a: bytes, b: bytes) -> bytes:
    """Bitwise AND of two equal-length byte strings."""
    return bytes(map(lambda x, y: x & y, a, b))


def b_or(a: bytes, b: bytes) -> bytes:
    """Bitwise OR of two equal-length byte strings."""
    return bytes(map(lambda x, y: x | y, a, b))


# Type predicates.
def is_number(x: Any) -> bool:
    """Return True if x can be interpreted as a number."""
    return to_s(x).isnumeric()


def is_bytes(x: Any) -> bool:
    """Return True if x is a bytes-like object."""
    return isinstance(x, bytes)


# Reflection helpers.
def class_name(x: Any) -> Any:
    """Return the class name of obj as a string."""
    return type(x).__name__ if inspect.isclass(x) else None


def timestamp(precise: bool = False) -> float:
    """Return the current time as an integer (or float when precise=True)."""
    return time.time() if precise else int(time.time())


# Address string helpers.
def bind_str(r: Any) -> str:
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


def get_bits(n: int, length: int, position: int = 0) -> int:
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


def neg_flip(result: float, x: float, y: float) -> float:
    """Return -result if x > y, otherwise result."""
    return -result if x > y else result


def numeric_distance(x: float, y: float) -> float:
    """Signed distance between two numbers: positive if y > x."""
    raw = max(x, y) - min(x, y)
    return neg_flip(raw, x, y)


# Short alias kept for backward compatibility.
n_dist = numeric_distance


# ---------------------------------------------------------------------------
# Randomness helpers
# ---------------------------------------------------------------------------


def rand_rang_alias() -> Callable[..., int]:
    """Alias kept for backward compatibility. Prefer random.randrange directly."""
    return random.randrange


def rand_b(n: int) -> bytes:
    """Return n random bytes from the OS entropy source."""
    return os.urandom(n)


def rand_b_readable(n: int) -> bytes:
    """Return n random printable ASCII bytes (letters, digits, space)."""
    chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    return bytes(random.choice(chars) for _ in range(n))


def rand_plain(n: int) -> bytes:
    """Return n random alphanumeric bytes (no spaces)."""
    charset = b"012345678abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return bytes(random.choice(charset) for _ in range(n))


def list_clone_rand(the_list: List[Any], n: int) -> List[Any]:
    """Return a randomly shuffled copy of the_list, trimmed to n elements."""
    the_clone = the_list[:]
    random.shuffle(the_clone)
    return the_clone[:n]


# ---------------------------------------------------------------------------
# List / dict utilities
# ---------------------------------------------------------------------------


def list_exclude_dict(
    key_name: str, exclusion: Any, entry_list: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
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
    key_name: str, criteria: Any, entry_list: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Return the first entry in entry_list where entry[key_name] == criteria."""
    for entry in entry_list:
        if key_name not in entry:
            continue

        if entry[key_name] == criteria:
            return entry

    return None


def file_get_contents(path: str) -> bytes:
    """Read and return the raw bytes of the file at path."""
    with open(path, mode="rb") as f:
        return f.read()


def to_type(x: Union[str, bytes], out_type: Union[str, bytes]) -> Union[str, bytes]:
    """Convert x to the same type as out_type (str or bytes)."""
    if isinstance(out_type, str):
        return to_s(x)
    return to_b(x)


def dict_child(x: Dict[str, Any], y: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge child dict x into template dict y.

    Returns a deep copy of y with any matching keys overwritten by x.
    y is the template (larger); x provides the overrides (smaller).
    """
    if len(x) > len(y):
        log(
            "dict_child: x has more keys than y — are the arguments in the right order?"
        )

    out = copy.deepcopy(y)
    for key in x:
        out[key] = x[key]
    return out


def dict_merge(x: Dict[str, Any], y: Dict[str, Any]) -> Dict[str, Any]:
    """Merge dict y into dict x in place and return x."""
    x.update(y)
    return x


# ---------------------------------------------------------------------------
# Binary utilities
# ---------------------------------------------------------------------------


def xor_bufs(a: bytes, b: bytes) -> bytes:
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


def bits_to_bytes(s: str) -> bytes:
    """Convert a binary string like '1010' to bytes."""
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder="big")


def buf_in_class(cls: Any, buf: Any) -> Union[str, bool]:
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


def hamming_weight(n: int) -> int:
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


def range_intersects(a: List[int], b: List[int]) -> bool:
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


def intersect_range(a: List[int], b: List[int]) -> List[int]:
    """
    Return the overlapping sub-range [start, end] of ranges a and b.

    Sorts all four endpoints together; the two middle values are the
    boundaries of the intersection in ascending order.
    """
    all_endpoints = sorted(a + b)
    return [all_endpoints[1], all_endpoints[2]]


def field_wrap(n: int, field: List[int]) -> int:
    """
    Wrap integer n so that it falls within [field[0], field[1]].

    Iterates until a stable value within the field is found.
    """
    start_range, stop_range = field
    stop_range += 1
    y = x = n % stop_range
    while True:
        if x < start_range:
            x += start_range
            y = x % stop_range
            if x != y:
                x = y
        if x == y:
            break
    return x


def field_dist(x: int, y: int, field: int) -> int:
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
    n_list: List[int], target: int, start_at: Optional[int] = None
) -> Optional[int]:
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

    for _ in range(list_len):
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
# Async utilities
# ---------------------------------------------------------------------------


def create_task(coro: Any, loop: Optional[Any] = None) -> Any:
    """Schedule coro as a task on the given (or current) event loop."""
    loop = loop or asyncio.get_event_loop()
    return loop.create_task(coro)


def get_running_loop():
    """Return the running event loop if one exists, falling back to get_event_loop() on Python < 3.7."""
    try:
        return asyncio.get_running_loop()
    except AttributeError:
        try:
            return asyncio.get_event_loop()
        except RuntimeError:
            return None
    except RuntimeError:
        return None


async def safe_run(f: Any, args: Optional[List[Any]] = None) -> None:
    """
    Run f(*args), then wait for all remaining tasks in the event loop to finish.

    Used as a wrapper in test harnesses.
    """
    if args is None:
        args = []
    await f(*args)

    tasks = asyncio.all_tasks()
    cur_task = asyncio.current_task()
    await asyncio.gather(*tasks - {cur_task})


async def return_true(result: Any = None) -> bool:
    """No-op coroutine that always returns True. Useful as a stub callback."""
    return True


async def threshold_gather(
    tasks: List[Any], result_filter: Callable[[List[Any]], List[Any]], threshold: int
) -> Optional[Any]:
    """
    Run tasks concurrently and return the first result that appears at least
    `threshold` times after applying result_filter.

    Returns None if no result reaches the threshold.
    """
    results = await asyncio.gather(*tasks)
    results = strip_none(results)
    results = sorted(result_filter(results))
    if not results:
        return None

    count = 0
    current = results[0]
    for value in results:
        if value == current:
            count += 1
        else:
            count = 1
            current = value

        if count >= threshold:
            return current

    return None


async def async_wrap_errors(
    coro: Any, timeout: Optional[int] = None, logging: bool = True
) -> Optional[Any]:
    """
    Await coro, optionally bounded by timeout seconds.

    Silently logs exceptions (except CancelledError which is re-raised).
    Returns the coroutine's result, or None if an exception occurred.
    """
    try:
        if timeout is None:
            return await coro
        if isinstance(timeout, int):
            return await asyncio.wait_for(coro, timeout)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except Exception:  # noqa: BLE001
        if logging:
            log("async_wrap_errors: exception caught")
            log_exception()


def sync_wrap_errors(
    f: Callable[..., Any], args: Optional[List[Any]] = None
) -> Optional[Any]:
    """
    Call f(*args) synchronously, logging any exception without re-raising.

    Returns the function's result, or None if an exception occurred.
    """
    try:
        if args:
            return f(*args)
        return f()
    except Exception:  # noqa: BLE001
        try:
            log_exception()
        except Exception:  # noqa: BLE001
            pass

    return None


async def async_retry(gen: Callable[[], Any], count: int, timeout: int = 4) -> None:
    """
    Retry the coroutine produced by gen() up to count times with the given timeout.

    gen() must return a tuple of (status_future, retry_coro, new_future_factory).
    Raises asyncio.TimeoutError if the retry limit is exceeded without success.
    """
    iteration = retries = 0
    while True:
        try:
            init_coro = gen()
            status_future, retry_coro, new_future = await asyncio.wait_for(
                init_coro, timeout
            )

            if iteration == 0:
                await retry_coro()

            status = await asyncio.wait_for(status_future, timeout)
            status_future = new_future()

            if status == STATUS_RETRY:
                iteration -= 1
                retries += 1
                await retry_coro()

            if status != STATUS_RETRY:
                return None

        except asyncio.TimeoutError:
            pass

        finally:
            iteration += 1
            if count in (iteration, retries):
                break

    raise asyncio.TimeoutError("async_retry: retry limit reached")


from .cleanup import (  # noqa: E402  # pylint: disable=cyclic-import
    cancel_task,
    cancel_tasks,
    rm_done_tasks,
    gather_or_cancel,
    handle_exceptions,
)


# Will be used in sample code to avoid boilerplate.
def async_test(coro: Any, loop: Optional[Any] = None) -> None:
    """
    Run a coroutine (or coroutine function) synchronously.

    Accepts either an already-created coroutine or a zero-argument coroutine
    function; calls it if it's a function.
    """
    if inspect.iscoroutinefunction(coro):
        coro = coro()

    if hasattr(asyncio, "run"):
        asyncio.run(coro)
    else:
        loop = loop or asyncio.get_event_loop()
        loop.run_until_complete(coro)


def async_to_sync(
    f: Callable[..., Any], params: Optional[Any] = None, loop: Optional[Any] = None
) -> Callable[..., Any]:
    """
    Wrap async function f into a synchronous callable.

    If params is provided, the returned closure accepts an args sequence.
    Otherwise the returned closure takes no arguments.

    Note: if there is already a running event loop (e.g. inside Jupyter),
    run nest_asyncio.apply() first to allow nested loops.
    """
    loop = loop or get_running_loop()

    if loop is None:
        raise RuntimeError(
            "async_to_sync: no event loop available. "
            "Pass loop= explicitly or call from inside a running loop."
        )

    if params is not None:

        def closure(args):
            """Run f with the provided args sequence synchronously on loop and return the result."""
            return loop.run_until_complete(f(*args))

        return closure

    def closure():
        """Run f with no arguments synchronously on loop and return the result."""
        return loop.run_until_complete(f())

        return closure


# ---------------------------------------------------------------------------
# Handler / pipe event dispatch
# ---------------------------------------------------------------------------


def handler_done_builder(
    pipe: Any, handler: Any, task: Optional[Any] = None
) -> Callable[[Any], None]:
    """
    Return a done-callback for a handler task attached to pipe.

    Removes the task from pipe.handler_tasks, logs integer error codes,
    and saves any new Task returned by the handler onto pipe.tasks.
    """

    def on_done(result):
        """Remove the completed task from pipe, log any error code, and track any returned Task."""
        if task in pipe.tasks:
            pipe.handler_tasks.remove(task)

        if isinstance(result, int) and result:
            log(
                fstr(
                    "> {0} = error {1}.",
                    (
                        handler,
                        result,
                    ),
                )
            )

        if isinstance(result, asyncio.Task):
            pipe.tasks.append(result)

    return on_done


def run_handler(
    pipe: Any,
    handler: Callable[..., Any],
    client_tup: Any,
    data: Optional[bytes] = None,
) -> None:
    """
    Dispatch a single handler on a received message.

    Async handlers are scheduled as tasks and tracked in pipe.handler_tasks.
    Sync handlers are called immediately.
    """
    if inspect.iscoroutinefunction(handler):
        task = create_task(handler(data, client_tup, pipe))
        task.add_done_callback(handler_done_builder(pipe, handler, task))
        pipe.handler_tasks.append(task)
    else:
        result = handler(data, client_tup, pipe)
        handler_done_builder(pipe, handler)(result)


def run_handlers(
    pipe: Any,
    handlers: List[Callable[..., Any]],
    client_tup: Any,
    data: Optional[bytes] = None,
) -> None:
    """
    Dispatch all registered handlers for a pipe event.

    Cleans up completed handler tasks before dispatching new ones.
    """
    pipe.handler_tasks = rm_done_tasks(pipe.handler_tasks)
    for handler in handlers:
        run_handler(pipe, handler, client_tup, data)


# ---------------------------------------------------------------------------
# Executor wrappers
# ---------------------------------------------------------------------------


def run_in_executor(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator that runs f in a thread-pool executor.

    Sync functions are passed directly to the executor.
    Async functions are run in a fresh event loop inside the executor.
    """

    @functools.wraps(f)
    def inner(*args, **kwargs):
        """Submit f to the thread-pool executor, running it in a new event loop if async."""
        loop = get_running_loop()

        if not inspect.iscoroutinefunction(f):
            return loop.run_in_executor(None, lambda: f(*args, **kwargs))

        def helper():
            """Run the async function f in a fresh event loop and return its result."""
            new_loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(new_loop)
                return new_loop.run_until_complete(f(*args, **kwargs))
            finally:
                new_loop.close()

        return loop.run_in_executor(None, helper)

    return inner


def run_in_executor2(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator that schedules async functions as tasks, or runs sync
    functions in the executor.
    """

    @functools.wraps(f)
    def inner(*args, **kwargs):
        """Schedule f as a task if async, or run it in the executor if sync."""
        loop = asyncio.get_event_loop()
        if inspect.iscoroutinefunction(f):
            return loop.create_task(f(*args, **kwargs))
        return loop.run_in_executor(None, lambda: f(*args, **kwargs))

    return inner


# ---------------------------------------------------------------------------
# Concurrency safety
# ---------------------------------------------------------------------------


async def safe_gather(*args: Any) -> List[Any]:
    """
    Gather coroutines, but run them sequentially on Python 3.5 to avoid
    filling the executor pool, which is buggy on older interpreter versions.
    """
    if sys.version_info[1] <= 5:
        results = []
        for task in args:
            result = await task
            results.append(result)
        return results
    return await asyncio.gather(*args)


async def sleep_random(min_ms: int = 100, max_ms: int = 2000) -> None:
    """Sleep for a random duration between min_ms and max_ms milliseconds."""
    delay = random.randrange(min_ms, max_ms + 1) / 1000.0
    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Cryptography utilities
# ---------------------------------------------------------------------------


def recover_verify_key(
    msg_b: bytes,
    sig_b: bytes,
    vk_b: Optional[bytes] = None,
    curve: Any = NIST192p,
    hashfunc: Any = hashlib.sha1,
) -> Any:
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


def find_intersect(list_a: List[Any], list_b: List[Any]) -> Iterator[Any]:
    """Yield values that appear in both list_a and list_b."""
    for a_val in list_a:
        for b_val in list_b:
            if a_val == b_val:
                yield a_val


def as_slice(needle: bytes, haystack: bytes) -> Optional[slice]:
    """Return a slice for the first occurrence of needle in haystack, or None."""
    pos = haystack.find(needle)
    if pos == -1:
        return None
    return slice(pos, pos + len(needle))


def is_ascii(data: Union[str, bytes]) -> bool:
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


def sqlite_dict_factory(cursor: Any, row: Any) -> Dict[str, Any]:
    """Row factory for sqlite3 that returns rows as dicts keyed by column name."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def what_exception() -> None:
    """
    Print a formatted summary of the current exception to stdout.

    Intended for debugging. Includes exception type, source file, line number,
    and full traceback.
    """
    exc_type, _, exc_tb = sys.exc_info()

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


def my_except_hook(exctype: Type[BaseException], value: BaseException, tb: Any) -> None:
    """Global exception hook that logs unexpected top-level exceptions."""
    log("Global except handler called.")
    log_exception()


def ensure_resolved(targets: Union[Any, List[Any]]) -> None:
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

if __name__ == "__main__":  # pragma: no cover
    assert not range_intersects([1, 1], [2, 2])
    assert range_intersects([1, 2], [2, 2])
    assert range_intersects([1, 2], [1, 2])
    assert range_intersects([1, 10], [5, 20])
    print("Self-tests passed.")
