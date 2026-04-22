"""Rules for selecting source address and interface when binding."""
import asyncio
import socket
import platform
from typing import Any, List, Optional, Tuple
from ...utility.utils import fstr
from ...net.net_defs import (
    VALID_AFS,
    IP4,
    IP6,
    IP_APPEND,
    IP_BIND_TUP,
    IP_PRIVATE,
    VALID_LOCALHOST,
    LOCALHOST_LOOKUP,
    V4_VALID_ANY,
    V6_VALID_ANY,
    V6_VALID_LOCALHOST,
)
from ..net_utils import ip_strip_if
from .bind_utils import match_bind_rule


# --- Reusable Logic Functions ---


def get_bind_magic_table(af: int) -> List[Any]:
    """
    Generates the table of edge-cases for bind() across platforms and AFs.
    """
    return [
        # Bypasses the need for interface details for localhost binds.
        ["*", VALID_AFS, IP_APPEND, VALID_LOCALHOST, LOCALHOST_LOOKUP[af], ""],
        # No interface added to IP for V6 ANY.
        ["*", IP6, IP_APPEND, V6_VALID_ANY, "::", ""],
        # Make sure to normalize unusual bind all values for v4.
        ["*", IP4, IP_APPEND, V4_VALID_ANY, "0.0.0.0", ""],
        # Windows needs the nic no added to v6 private IPs.
        ["Windows", IP6, IP_APPEND, IP_PRIVATE, "", "nic_id"],
        # ... whereas other operating systems use the interface name.
        ["*", IP6, IP_APPEND, IP_PRIVATE, "", "nic_id"],
        # Windows v6 bind any doesn't need scope ID.
        ["Windows", IP6, IP_BIND_TUP, V6_VALID_ANY, None, [3, 0]],
        # Localhost V6 bind tups don't need the scope ID.
        ["*", IP6, IP_BIND_TUP, V6_VALID_LOCALHOST, None, [3, 0]],
        # Other private v6 bind tups need the scope id in Windows.
        ["Windows", IP6, IP_BIND_TUP, IP_PRIVATE, None, [3, "nic_id"]],
    ]


def resolve_bind_ip(
    ip: str, af: int, nic_id: Any, plat: str, bind_magic: List[Any]
) -> str:
    """
    Processes IP_APPEND rules to normalize the IP string before lookup.
    """
    for bind_rule in bind_magic:
        rule_match = match_bind_rule(ip, af, plat, bind_rule, IP_APPEND)
        if not rule_match:
            continue

        # Do norm rule.
        if rule_match.norm == "":
            pass  # Todo: norm IP.
        elif rule_match.norm is not None:
            ip = rule_match.norm

        # Do logic specific to IP_APPEND.
        if rule_match.change is not None:
            if rule_match.change == "nic_id":
                ip += fstr("%{0}", (nic_id,))
            else:
                ip += rule_match.change

        # Only one rule ran per type.
        break

    return ip


def resolve_bind_tuple(
    initial_tup: Tuple[Any, ...],
    ip: str,
    af: int,
    nic_id: Any,
    plat: str,
    bind_magic: List[Any],
) -> Tuple[Any, ...]:
    """
    Processes IP_BIND_TUP rules to modify the tuple (e.g. Scope IDs) after lookup.
    """
    bind_tup = initial_tup
    # ip = ip_norm(initial_tup[0]) # Strip % from IP for consistency.
    # bind_tup = [ip, ] + bind_tup[1:]

    for bind_rule in bind_magic:
        # Skip rule types we're not processing.
        rule_match = match_bind_rule(ip, af, plat, bind_rule, IP_BIND_TUP)
        if not rule_match:
            continue

        # Apply changes to the bind tuple.
        offset, val_str = rule_match.change
        if val_str == "nic_id":
            val = nic_id
        else:
            val = val_str

        bind_tup = list(bind_tup)
        # Check offset range to be safe
        if offset < len(bind_tup):
            bind_tup[offset] = val

        bind_tup = tuple(bind_tup)

        # Only one rule ran per type.
        break

    """
    On recent versions of getaddr info when you pass in ip%scope_id
    the function returns the 4 tuple bind address with the scope_id
    portion stripped from the IP and only in the fourth field.
    Older versions don't do that, hence keep the tup consistent.
    """
    if af == IP6:
        bind_tup = (ip_strip_if(bind_tup[0]),) + bind_tup[1:]

    return bind_tup


# --- Main Functions ---


async def binder_async(
    af: int,
    ip: str = "",
    port: int = 0,
    nic_id: Optional[Any] = None,
    plat: str = platform.system(),
) -> Optional[Tuple[Any, ...]]:
    """
    Async version of the binder.
    """
    # 1. Get Rules and Prepare IP
    bind_magic = get_bind_magic_table(af)
    ip = resolve_bind_ip(ip, af, nic_id, plat, bind_magic)

    # 2. Lookup correct bind tuples to use (Async)
    loop = asyncio.get_event_loop()
    try:
        addr_infos = await asyncio.wait_for(loop.getaddrinfo(ip, port), timeout=2.0)
    except (OSError, asyncio.TimeoutError):
        addr_infos = []

    # Fail gracefully if lookup failed (or handle as per original logic)
    if not addr_infos:
        return None

    initial_tup = addr_infos[0][4]

    # 3. Finalize Tuple
    return resolve_bind_tuple(initial_tup, ip, af, nic_id, plat, bind_magic)


def binder_sync(
    af: int,
    ip: str = "",
    port: int = 0,
    nic_id: Optional[Any] = None,
    plat: str = platform.system(),
) -> Optional[Tuple[Any, ...]]:
    """
    Synchronous version of the binder.
    """
    # 1. Get Rules and Prepare IP
    bind_magic = get_bind_magic_table(af)
    ip = resolve_bind_ip(ip, af, nic_id, plat, bind_magic)

    # 2. Lookup correct bind tuples to use (Sync)
    try:
        addr_infos = socket.getaddrinfo(ip, port)
    except OSError:
        addr_infos = []

    # Fail gracefully if lookup failed (or handle as per original logic)
    if not addr_infos:
        return None

    initial_tup = addr_infos[0][4]

    # 3. Finalize Tuple
    return resolve_bind_tuple(initial_tup, ip, af, nic_id, plat, bind_magic)
