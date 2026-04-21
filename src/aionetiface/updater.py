import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from .servers import INFRA, INFRA_BUF
from .net.address import Address
from .protocol.http.http_client_lib import WebCurl
from .install import get_aionetiface_install_root, copy_aionetiface_install_files_as_needed
from .utility.utils import to_s, log_exception
from .utility.error_logger import log

__all__ = ["reconcile_lists", "reconcile_infra", "update_server_list"]

"""
Some existing code relies on preserving offsets for server
entries so this keeps existing servers in place.
"""
def reconcile_lists(old_list: List[Any], new_list: List[Any]) -> List[Any]:
    def get_id(x):
        return x[0]["id"]

    new_by_id = {get_id(x): x for x in new_list}
    old_by_id = {get_id(x): x for x in old_list}
    old_ids = set(old_by_id.keys())

    out = []
    for x in old_list:
        x_id = get_id(x)
        if x_id in new_by_id:
            # merge: use the new item
            new_item = new_by_id[x_id].copy()

            # if both port and old_port exist, swap them
            if "port" in new_item[0] and "old_port" in old_by_id[x_id][0]:
                new_item[0]["port"], new_item[0]["old_port"] = old_by_id[x_id][0]["old_port"], new_item[0]["port"]

            out.append(new_item)
        else:
            # copy the old item and set port to 0
            item_copy = x.copy()
            item_copy[0]["old_port"] = item_copy[0]["port"]
            item_copy[0]["port"] = 0
            out.append(item_copy)

    # append new items not in old_list
    for x in new_list:
        x_id = get_id(x)
        if x_id not in old_ids:
            out.append(x)

    return out

"""
TODO: just use a different address format for these.
"""
def reconcile_infra(old_infra: Dict[str, Any], new_infra: Dict[str, Any]) -> None:
    names = ("MQTT", "TURN",)
    for name in names:
        for af_str in ("IPv4", "IPv6"):
            for proto_str in ("UDP", "TCP"):
                try:
                    new_infra[name][af_str][proto_str] = reconcile_lists(
                        old_infra[name][af_str][proto_str],
                        new_infra[name][af_str][proto_str]
                    )
                except (KeyError, TypeError):
                    log_exception()

async def update_server_list(nic: Any, sys_clock: Any = time, init_infra_buf: Any = INFRA_BUF, init_infra: Any = INFRA) -> Tuple[bool, Any, Any]:
    copy_aionetiface_install_files_as_needed()
    install_root = get_aionetiface_install_root()
    servers_path = os.path.join(install_root, "servers.json")
    
    # Set to in-built server list.
    infra_buf = init_infra_buf
    infra = init_infra
    update_req = False

    # If the currently set server list is more than a month old
    # see if the stored server list is more recent.
    one_month_sec = 2592000
    if (sys_clock.time() - infra["timestamp"]) >= one_month_sec:
        # Load pre-existing server list.
        stored_json = None
        stored_infra = None
        if os.path.exists(servers_path):
            try:
                with open(servers_path, 'r') as fp:
                    stored_json = fp.read()
                stored_infra = json.loads(stored_json)
            except (OSError, ValueError):
                # Corrupted or truncated file; keep the built-in list.
                log("Stored server file unreadable; using built-in list.")
                log_exception()
                stored_infra = None

            # If the stored server list is more recent -- use that instead.
            if stored_infra:
                if stored_infra.get("timestamp", 0) > infra["timestamp"]:
                    infra = stored_infra
                    infra_buf = stored_json

    # If server list is still more than a month old attempt to update it.
    if (sys_clock.time() - infra["timestamp"]) >= one_month_sec:
        try:
            addr = ("ovh1.p2pd.net", 8000)
            client = WebCurl(addr, nic.route())
            resp = await client.get("/servers")
            resp_buf = to_s(resp.out)
            resp_infra = json.loads(resp_buf)

            # Basic output validation.
            # If server crashes, has a bug, etc, might not return anything.
            if "timestamp" in resp_infra:
                infra_buf = resp_buf
                infra = resp_infra
                update_req = True
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log("Cannot fetch new server list.")
            log_exception()

    # Save server list if none exists.
    if not os.path.exists(servers_path):
        update_req = True

    # Update the saved server file.
    # Only update it if needed.
    if update_req:
        # Write to a temp file.
        tmp_path = servers_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fp:
            fp.write(infra_buf)

        # Replace original server list with temp file.
        os.replace(tmp_path, servers_path)

    # Can then be used to update env variables.
    return update_req, infra_buf, infra