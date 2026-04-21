import asyncio
import binascii
import copy
import ctypes
import functools
import hashlib
import inspect
import ipaddress
import itertools
import logging
import math
import multiprocessing
import os
import platform
import random
import re
import selectors
import sys
import time
import traceback
import unittest
import urllib.parse
from concurrent.futures import ProcessPoolExecutor
from decimal import Decimal as Dec
from ecdsa.curves import NIST192p
import ecdsa

from .fstr import fstr
from .error_logger import *


# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------

vmaj, vmin, _ = platform.python_version_tuple()
vmaj = int(vmaj)
vmin = int(vmin)

if vmaj < 3:
    raise Exception("Python 2 not supported.")

if vmin < 5:
    raise Exception("Non-Windows OS needs Python 3.5 or higher")

if vmin < 8 and sys.platform == 'win32':
    pass  # Windows 3.8+ preferred but not enforced for now


# ---------------------------------------------------------------------------
# asyncio compatibility shim for Python < 3.7
# ---------------------------------------------------------------------------

if not hasattr(asyncio, 'create_task'):
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

def to_b(x):
    """Convert x to bytes. Passes through if already bytes."""
    return x if type(x) == bytes else x.encode("ascii", errors='ignore')

def to_s(x):
    """Convert x to str. Passes through if already str."""
    return x if type(x) == str else x.decode("utf-8", errors='ignore')

# Hex string conversions.
to_hs = lambda x: to_s(binascii.hexlify(to_b(x)))
to_h  = lambda x: to_hs(x) if len(x) else "00"

# Integer / numeric conversions.
to_i = lambda x: x if isinstance(x, int) else int(x, 16)
to_n = lambda x: x if isinstance(x, int) else int(to_s(x), 10)

# Integer <-> bytes conversions.
i_to_b = lambda x, o='little': x.to_bytes((x.bit_length() + 7) // 8, o)
b_to_i = lambda x, o='little': int.from_bytes(x, o)
h_to_b = lambda x, o='little': binascii.unhexlify(to_b(x))

# IP address helper.
ip_f = ipaddress.ip_address

# Regex / string helpers.
re.unescape   = lambda x: re.sub(r'\\(.)', r'\1', x)
rm_whitespace = lambda x: re.sub(r"\s+", "", x, flags=re.UNICODE)
urlencode     = lambda x: to_b(urllib.parse.quote(x))
urldecode     = lambda x: to_b(urllib.parse.unquote(x))

# Hash helpers.
sha256    = lambda x: to_s(hashlib.sha256(to_b(x)).hexdigest())
hash160   = lambda x: hashlib.new('ripemd160', to_b(x)).hexdigest()
sha3_256  = lambda x: to_s(hashlib.sha3_256(to_b(x)).hexdigest())
b_sha3_256 = lambda x: hashlib.sha3_256(to_b(x)).digest()

# Deterministic hash: converts x to a string, hashes it, returns int.
dhash = lambda x: b_to_i(hashlib.sha256(to_b(fstr("{0}", (x,)))).digest())

def rendezvous_score(*tokens: bytes) -> float:
    """Highest-random-weight score for a server in rendezvous hashing.

    Hash all tokens concatenated with SHA-256 and map to an exponentially
    distributed score via -log(U).  Higher score = preferred server.
    Call once per (key, server) pair; rank servers by score descending.

    All tokens must be bytes — callers are responsible for converting ints,
    strings, etc. before calling (e.g. bytes([af]), to_b(host), ...).
    """
    digest = hashlib.sha256(b"".join(tokens)).digest()
    u = (int.from_bytes(digest, "big") + 1) / (2 ** 256)
    return -math.log(u)

# Port helpers.
valid_port = lambda p: p >= 1 and p <= MAX_PORT
port_wrap  = lambda p: (p % MAX_PORT) or 1

# List / dict helpers.
to_unique      = lambda x: [i for n, i in enumerate(x) if i not in x[:n]]
strip_none     = lambda x: [i for i in x if i is not None]
shuffle        = lambda x: random.shuffle(x) or x
d_keys         = lambda x: list(x.keys())
d_vals         = lambda x: list(x.values())
list_join      = lambda l: list(itertools.chain.from_iterable(l))
list_x_to_dict = lambda x: [v.dict() for v in x]

# Numeric / range helpers.
from_range = lambda r: random.randrange(r[0], r[1] + 1)
in_range   = lambda x, r: x >= r[0] and x <= r[1]
len_range  = lambda r: r[1] - r[0]
dict_plus  = lambda d, k: d[k] if k in d else 0

# Byte-level bitwise operations.
b_and = lambda a, b: bytes(map(lambda x, y: x & y, a, b))
b_or  = lambda a, b: bytes(map(lambda x, y: x | y, a, b))

# Type predicates.
is_number = lambda x: to_s(x).isnumeric()
is_bytes  = lambda x: isinstance(x, bytes)

# Reflection helpers.
class_name = lambda x: type(x).__name__ if inspect.isclass(x) else None
timestamp  = lambda precise=False: time.time() if precise else int(time.time())

# Address string helpers.
bind_str = lambda r: fstr("{0}:{1}", (r.bind_tup()[0], r.bind_tup()[1],))

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
    """Return n random bytes."""
    buf = b""
    for i in range(n):
        buf += bytes([random.randrange(256)])
    return buf

def rand_b_readable(n):
    """Return n random printable ASCII bytes (letters, digits, space)."""
    chars = (
        b"abcdefghijklmnopqrstuvwxyz"
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"0123456789 "
    )
    buf = b""
    for _ in range(n):
        buf += bytes([random.choice(chars)])
    return buf

def rand_plain(n):
    """Return n random alphanumeric bytes (no spaces)."""
    charset = (
        b"012345678abcdefghijklmnopqrs"
        b"tuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )
    buf = b""
    for _ in range(n):
        ch = random.choice(charset)
        buf += bytes([ch])
    return buf

def list_clone_rand(the_list, n):
    """Return a randomly shuffled copy of the_list, trimmed to n elements."""
    the_clone = the_list[:]
    random.shuffle(the_clone)
    return the_clone[:n]


# ---------------------------------------------------------------------------
# List / dict utilities
# ---------------------------------------------------------------------------

def list_exclude_dict(key_name, exclusion, entry_list):
    """Return entry_list without entries where entry[key_name] == exclusion."""
    result = []
    for entry in entry_list:
        if key_name not in entry:
            result.append(entry)
            continue

        if entry[key_name] != exclusion:
            result.append(entry)

    return result

def list_get_dict(key_name, criteria, entry_list):
    """Return the first entry in entry_list where entry[key_name] == criteria."""
    for entry in entry_list:
        if key_name not in entry:
            continue

        if entry[key_name] == criteria:
            return entry

def file_get_contents(path):
    """Read and return the raw bytes of the file at path."""
    with open(path, mode='rb') as f:
        return f.read()

def to_type(x, out_type):
    """Convert x to the same type as out_type (str or bytes)."""
    if isinstance(out_type, str):
        return to_s(x)
    if isinstance(out_type, bytes):
        return to_b(x)

def dict_child(x, y):
    """
    Merge child dict x into template dict y.

    Returns a deep copy of y with any matching keys overwritten by x.
    y is the template (larger); x provides the overrides (smaller).
    """
    if len(x) > len(y):
        log("dict_child: x has more keys than y — are the arguments in the right order?")

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

    return bytes(result)[:min(a_len, b_len)]

def bits_to_bytes(s):
    """Convert a binary string like '1010' to bytes."""
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def buf_in_class(cls, buf):
    """
    Search cls for a member whose value equals buf.

    Returns the member name if found, False otherwise.
    """
    for member in dir(cls):
        val = getattr(cls, member)
        if type(val) != type(buf):
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

def sorted_search(n_list, target, start_at=None):
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
            else:
                index -= int(index / 2) or 1
        else:
            index += int(index / 2) or 1

        if index >= list_len - 1:
            return list_len - 1

    raise Exception("sorted_search: list may not be sorted.")


# ---------------------------------------------------------------------------
# Async utilities
# ---------------------------------------------------------------------------

def create_task(coro, loop=None):
    """Schedule coro as a task on the given (or current) event loop."""
    loop = loop or asyncio.get_event_loop()
    return loop.create_task(coro)

def get_running_loop():
    """
    Return the currently running event loop, or None if there isn't one.

    Uses asyncio.get_running_loop() on Python 3.7+, falls back to
    get_event_loop() on older versions.
    """
    try:
        if sys.version_info[1] >= 7:
            return asyncio.get_running_loop()
        else:
            return asyncio.get_event_loop()
    except RuntimeError:
        return None

async def safe_run(f, args=None):
    """
    Run f(*args), then wait for all remaining tasks in the event loop to finish.

    Used as a wrapper in test harnesses on older Python versions.
    """
    if args is None:
        args = []
    await f(*args)

    try:
        tasks = asyncio.Task.all_tasks()
        cur_task = asyncio.Task.current_task()
    except (AttributeError, RuntimeError):
        tasks = asyncio.all_tasks()
        cur_task = asyncio.current_task()

    await asyncio.gather(*tasks - {cur_task})

async def return_true(result=None):
    """No-op coroutine that always returns True. Useful as a stub callback."""
    return True

async def threshold_gather(tasks, result_filter, threshold):
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

async def async_wrap_errors(coro, timeout=None, logging=True):
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
    except asyncio.CancelledError:
        raise
    except Exception:
        if logging:
            log("async_wrap_errors: exception caught")
            log_exception()

def sync_wrap_errors(f, args=None):
    """
    Call f(*args) synchronously, logging any exception without re-raising.

    Returns the function's result, or None if an exception occurred.
    """
    try:
        if args:
            return f(*args)
        else:
            return f()
    except Exception:
        try:
            log_exception()
        except Exception:
            pass

async def async_retry(gen, count, timeout=4):
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
                async_wrap_errors(init_coro),
                timeout
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

from .cleanup import (
    cancel_task, cancel_tasks, rm_done_tasks,
    gather_or_cancel, handle_exceptions,
)

# Will be used in sample code to avoid boilerplate.
def async_test(coro, loop=None):
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

def async_to_sync(f, params=None, loop=None):
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
            return loop.run_until_complete(f(*args))
        return closure
    else:
        def closure():
            return loop.run_until_complete(f())
        return closure


# ---------------------------------------------------------------------------
# Handler / pipe event dispatch
# ---------------------------------------------------------------------------

def handler_done_builder(pipe, handler, task=None):
    """
    Return a done-callback for a handler task attached to pipe.

    Removes the task from pipe.handler_tasks, logs integer error codes,
    and saves any new Task returned by the handler onto pipe.tasks.
    """
    def on_done(result):
        if task in pipe.tasks:
            pipe.handler_tasks.remove(task)

        if isinstance(result, int) and result:
            log(fstr("> {0} = error {1}.", (handler, result,)))

        if isinstance(result, asyncio.Task):
            pipe.tasks.append(result)

    return on_done

def run_handler(pipe, handler, client_tup, data=None):
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

def run_handlers(pipe, handlers, client_tup, data=None):
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

def run_in_executor(f):
    """
    Decorator that runs f in a thread-pool executor.

    Sync functions are passed directly to the executor.
    Async functions are run in a fresh event loop inside the executor.
    """
    @functools.wraps(f)
    def inner(*args, **kwargs):
        loop = get_running_loop()

        if not inspect.iscoroutinefunction(f):
            return loop.run_in_executor(None, lambda: f(*args, **kwargs))

        def helper():
            new_loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(new_loop)
                return new_loop.run_until_complete(f(*args, **kwargs))
            finally:
                new_loop.close()

        return loop.run_in_executor(None, helper)

    return inner

def run_in_executor2(f):
    """
    Decorator that schedules async functions as tasks, or runs sync
    functions in the executor.
    """
    @functools.wraps(f)
    def inner(*args, **kwargs):
        loop = asyncio.get_event_loop()
        if inspect.iscoroutinefunction(f):
            return loop.create_task(f(*args, **kwargs))
        else:
            return loop.run_in_executor(None, lambda: f(*args, **kwargs))
    return inner


# ---------------------------------------------------------------------------
# Concurrency safety
# ---------------------------------------------------------------------------

async def safe_gather(*args):
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
    else:
        return await asyncio.gather(*args)

async def sleep_random(min_ms=100, max_ms=2000):
    """Sleep for a random duration between min_ms and max_ms milliseconds."""
    delay = random.randrange(min_ms, max_ms + 1) / 1000.0
    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Cryptography utilities
# ---------------------------------------------------------------------------

def recover_verify_key(msg_b, sig_b, vk_b=None, curve=NIST192p, hashfunc=hashlib.sha1):
    """
    Recover ECDSA verify key(s) from a signature.

    If vk_b is provided, raises if that key is not among the recovered keys.
    Returns the first recovered key that successfully verifies the signature.
    """
    vk_list = ecdsa.VerifyingKey.from_public_key_recovery(
        signature=sig_b,
        data=msg_b,
        curve=curve,
        hashfunc=hashfunc
    )

    if vk_b is not None:
        if not any(vk.to_string("compressed") == vk_b for vk in vk_list):
            raise Exception("recover_verify_key: expected key not found in recovered set.")

    for vk in vk_list:
        try:
            vk.verify(sig_b, msg_b)
            return vk
        except ecdsa.BadSignatureError:
            continue

    raise Exception("recover_verify_key: no recovered key could verify the signature.")


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
            data.decode('ascii')
            return True
        except UnicodeDecodeError:
            return False
    else:
        try:
            data.encode('ascii')
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
    exc_type, exc_value, exc_tb = sys.exc_info()

    fname = "Unknown"
    lineno = 0

    if exc_tb is not None:
        curr_tb = exc_tb
        while curr_tb.tb_next:
            curr_tb = curr_tb.tb_next

        try:
            if hasattr(curr_tb, 'tb_frame') and curr_tb.tb_frame:
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
            raise Exception(
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
