"""Windows network interface enumeration via WMIC output parsing."""
import ast
import re
import asyncio
import sys

if sys.platform == "win32":
    pass

from typing import Any, Dict, List, Tuple
from ....net.net_utils import IP4, IP6, VALID_AFS
from ....utility.cmd_tools import cmd
from ....utility.utils import safe_gather
from ....net.ip_range import IPRange
from ....net.net_utils import ip_norm


def parse_wmic_list(entry: str) -> List[Any]:
    """Returns a Python list parsed from a WMIC-formatted brace-delimited string."""
    if not len(entry):
        return []

    if entry[0] == "{":
        if entry[1] not in ("'", '"'):
            entry = '{"' + entry[1:-1] + '"}'

    entry = entry.replace("{", "[")
    entry = entry.replace("}", "]")

    return ast.literal_eval(entry)


def parse_wmic_addrs(addrs: List[str]) -> Dict[Any, List[Dict[str, Any]]]:
    """Returns address info records grouped by address family for the given list of IP strings."""
    addr_info = {IP4: [], IP6: []}
    for addr in addrs:
        ipr = IPRange(addr)
        addr_info[ipr.af].append(
            {
                "addr": addr,
                "af": ipr.af,
                # Both just placeholders / incorrect.
                # TODO: get real values in the future.
                "host_limit": ipr.host_limit,
                "netmask": ipr.netmask,
            }
        )

    return addr_info


class WMICParse:
    """Parses WMIC command output into structured network interface data."""

    @staticmethod
    def show_main(af: Any, msg: str) -> List[Any]:
        """Returns a list of fully parsed interface records including addresses, gateways, and GUIDs."""
        p = r"({[^{}]+})?\s{2,}([^{}\r\n]+?) {2,}([0-9]+)\s+"
        p += r"({[^{}]+})\s+([^\s]+)\s+({[^{}]+})"
        out = re.findall(p, msg)
        results = []
        for match_group in out:
            # Name the match group fields.
            gw_ips, if_name, if_index, if_ips, mac, guid = match_group
            gw_ips = parse_wmic_list(gw_ips)
            if_ips = parse_wmic_list(if_ips)

            # Put GWs into right format for netifaces.
            gws = {IP4: None, IP6: None}
            gws_addrs = parse_wmic_addrs(gw_ips)
            for af in VALID_AFS:
                if len(gws_addrs[af]):
                    gws[af] = gws_addrs[af][0]["addr"]
                    break

            # Record interface results.
            results.append(
                {
                    "guid": guid,
                    "name": if_name,
                    "no": int(if_index),
                    "mac": mac,
                    "addr": parse_wmic_addrs(if_ips),
                    "gws": gws,
                    # Todo:
                    "defaults": None,
                    "con_name": None,
                }
            )

        return [af, "main", results]

    @staticmethod
    def show_con_names(af: Any, msg: str) -> List[Any]:
        """Returns a list of connection name records indexed by interface index."""
        p = r"([0-9]+)[ \t]+([^\r\n]+?) {2,}[ \t]*"
        out = re.findall(p, msg)
        results = {}
        for match_group in out:
            if_index, name = match_group
            if if_index not in results:
                results[if_index] = {"if_index": if_index, "con_name": name}

        return [af, "con_names", results]

    # route print
    # Also has ipv6 results.
    # if_index: ... if_name, mac
    @staticmethod
    def show_routes(af: Any, msg: str) -> List[Any]:
        """Returns a list of parsed route and MAC records including default gateway entries."""
        p = r"([0-9]+)\s*[.]{2,}([0-9a-fA-F ]+)[ .]+([^\r\n]+)[\r\n]"
        out = re.findall(p, msg)
        results = {"default": {IP4: None, IP6: None}}
        for match_group in out:
            if_index, mac, if_name = match_group
            mac = mac.strip().lower()
            mac = mac.replace(" ", "-")
            results[if_index] = {"if_name": if_name, "mac": mac}

        # Setup entries for default gateways IP4.
        p = r"0[.]0[.]0[.]0\s+0[.]0[.]0[.]0\s+([^\s]+)\s+([^\s]+)\s+[0-9]+"
        out = re.findall(p, msg)
        if len(out):
            gw_ip, if_ip = out[0]
            results["default"][IP4] = {"gw_ip": gw_ip.strip(), "if_ip": if_ip.strip()}

        # Setup entries for default gateways IP6.
        p = r"[0-9]+\s+[0-9]+\s+::\/0\s+([^\s]+)"
        out = re.findall(p, msg)
        if len(out):
            gw_ip = out[0]
            results["default"][IP6] = {"gw_ip": gw_ip.strip()}

        return [af, "routes", results]


async def do_wmic_cmds() -> List[Any]:
    parser = WMICParse()
    cmd_vectors = [
        [
            parser.show_main,
            {
                IP4: "wmic nicconfig where IPEnabled=true get Description, IPAddress, DefaultIPGateway, Index, MACAddress, SettingID",
            },
            False,
        ],
        [
            parser.show_con_names,
            {
                IP4: "wmic nic get Index, NetConnectionID",
            },
            False,
        ],
        [
            parser.show_routes,
            {
                IP4: "route print",
            },
            False,
        ],
    ]

    async def helper(cmd_txt, out_handler):
        out = await cmd(cmd_txt)
        return out_handler(None, out)

    # Build list of commands to run.
    tasks = []
    for vector in cmd_vectors:
        out_handler, cmd_meta, _ = vector
        task = helper(cmd_meta[IP4], out_handler)
        tasks.append(task)

    # Run commands concurrently or not.
    return await safe_gather(*tasks)


async def get_ipv6_from_netsh() -> Dict[str, Tuple[int, List[Dict[str, Any]]]]:
    """
    Parse 'netsh interface ipv6 show address' to get IPv6 addresses per interface.

    Returns {con_name: (scope_id, [addr_info_dicts])}.
    Used on Windows XP where WMIC nicconfig does not include IPv6 addresses.
    """
    try:
        out = await cmd("netsh interface ipv6 show address")
    except Exception:
        return {}

    result = {}
    current_name = None
    current_no = None

    for line in out.splitlines():
        stripped = line.strip()
        m = re.match(r"Interface\s+(\d+):\s+(.+)", stripped)
        if m:
            current_no = int(m.group(1))
            current_name = m.group(2).strip()
            result[current_name] = (current_no, [])
            continue

        if current_name is None:
            continue

        parts = stripped.split()
        if len(parts) < 5:
            continue

        addr_str = parts[-1]
        try:
            ipr = IPRange(addr_str)
            if ipr.af == IP6:
                result[current_name][1].append(
                    {
                        "addr": ip_norm(addr_str),
                        "af": IP6,
                        "host_limit": ipr.host_limit,
                        "netmask": ipr.netmask,
                    }
                )
        except Exception:
            pass

    return result


async def if_infos_from_wmic() -> List[Dict[str, Any]]:
    # Get NIC info from different WMIC cmds.
    results = await do_wmic_cmds()

    # Index by key.
    by_name = {}
    for result in results:
        _, k, v = result
        by_name[k] = v

    # Build MAC -> route-print interface index map.
    # 'route print' uses the same index that Windows embeds in IPv6 link-local
    # scope IDs (the %N suffix). WMIC nicconfig Index can differ on older
    # Windows versions (Vista, Win7), causing bind() to fail with WinError 10049.
    mac_to_route_idx = {}
    for idx_str, route_info in by_name["routes"].items():
        if idx_str == "default":
            continue
        mac_to_route_idx[route_info["mac"]] = int(idx_str)

    # Consolidate everything into main.
    ret = []
    for entry in by_name["main"]:
        # Special index for NICs — use WMIC index for con_names lookup.
        if_index = str(entry["no"])

        # Skip inactive connections.
        if if_index not in by_name["con_names"]:
            continue

        # Record con_name for an if.
        con_name = by_name["con_names"][if_index]["con_name"]
        entry["con_name"] = con_name

        # Overwrite 'no' with the route-print index so that IPv6 scope IDs
        # embedded in socket bind tuples match the %N shown in ipconfig /all.
        entry_mac = entry["mac"].lower().replace(":", "-").replace(" ", "-")
        if entry_mac in mac_to_route_idx:
            entry["no"] = mac_to_route_idx[entry_mac]

        # Fill in default gateway defaults.
        defaults = []
        for af in [IP4, IP6]:
            gw_info = by_name["routes"]["default"]
            if gw_info[af] is None:
                continue

            # Does gw interface IP match this IF?
            # if_ip is absent for IPv6 routes and on some older Windows versions.
            if_ip = gw_info[af].get("if_ip")
            if not if_ip:
                continue
            gw_if_ipr = IPRange(if_ip)
            for addr_info in entry["addr"][af]:
                if_ipr = IPRange(addr_info["addr"])
                if if_ipr == gw_if_ipr:
                    defaults.append(af)
                    break

        # List of AFs this if is the main interface for.
        entry["defaults"] = defaults
        ret.append(entry)

    # Fallback: if route print returned no usable default route (e.g., partial
    # output on a slow/old machine under load), use WMIC's own DefaultIPGateway
    # field to determine which NIC is the default for each AF.
    any_defaults = any(e["defaults"] for e in ret)
    if not any_defaults:
        for af in [IP4, IP6]:
            route_default = by_name["routes"]["default"].get(af)
            for entry in ret:
                if entry["gws"][af] is None:
                    continue
                # If route print has a gateway, verify it matches this NIC's WMIC gateway.
                if route_default is not None and entry["gws"][af] != route_default.get("gw_ip"):
                    continue
                entry["defaults"].append(af)
                break

    # On Windows XP, WMIC nicconfig does not include IPv6 addresses.
    # Supplement any NIC that has no IPv6 addresses from netsh, which also
    # gives us the correct IPv6 scope ID to store in entry["no"].
    any_missing_v6 = any(not e["addr"][IP6] for e in ret)
    if any_missing_v6:
        netsh_v6 = await get_ipv6_from_netsh()
        for entry in ret:
            if entry["addr"][IP6]:
                continue
            con_name = entry.get("con_name", "")
            if con_name not in netsh_v6:
                continue
            scope_id, addr_infos = netsh_v6[con_name]
            if addr_infos:
                entry["addr"][IP6] = addr_infos
                entry["no"] = scope_id

    return ret


async def workspace() -> None:

    results = await if_infos_from_wmic()
    print(results)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(workspace())
