"""
This module is a drop-in replacement for netifaces on Windows.
Usage is simply:
    from aionetiface import *
    async def main():
        netifaces = await aionetiface_setup_netifaces()

The pypi netifaces module has several problems on Windows OS':

1. It requires a distribution of VS C++ Build Tools 20**.
Having users install the right build tools to get the software
working is complex and error-prone. It also makes packaging
software that uses netifaces much more difficult.

2. On recent versions of Windows it displays meaningless
strings of GUIDs over network interface names. Consequently,
one has to do a series of reg hacks, privilege elevations,
and patches to use the library with human-readable names.

The most portable way to do complex operations on Windows
seems to be to use powershell scripting. Looking up certain
registry keys isn't guaranteed to work as the locations may
change between versions. The networking tools available in
cmd.exe are now being phased out in favor of the tools
available in powershell. Powershell is now widely supported
even on older Windows OS.

The downside to using powershell to obtain relevant NIC
information is it's slow. A process needs to be spawned
for each new command. In order to prevent errors on certain
Windows versions concurrency also has to be disabled. This
doesn't seem to effect speed too much but the code is many
times slower than netiface. Nevertheless, it's more
portable and doesn't require privilege elevations to get
human-readable network interface descriptions.

Speedups:

I've added a new feature to obtain all the networking info
from a single powershell script. The program will attempt
to use this script if powershell is unrestricted. If it
fails to load interfaces with regular commands it will
try relaunch with a UAC prompt, unrestrict powershell,
then attempt to run the script in powershell.

Registry:

Don't attempt to write a new version of this using the
Windows registry. The registry does not make available
simple access to the interface numbers and a special
(undocumented) algorithm needs to be used to rank the
interfaces and derive the number. Doing this is unsupported
outside of using heavy Windows SDK dependencies.

Notes:
    - These commands don't seem to require special permissions.
    - They need to use double quotes or the command won't run.
    - Tested as working with execution policy = restricted.
    - Is there a way to convert the PS1 script to a single line
    command and have it passed to powershell without execution perms?
"""

import asyncio
import re
import platform
from ....net.net_defs import IP4, IP6, VALID_AFS
from ....net.net_utils import cidr_to_netmask, v_to_af, ip_strip_if, ip_strip_cidr, af_bitlen
from ....net.ip_range import IPRange
from ....utility.utils import fstr, log, log_exception, to_n, ip_f
from ....utility.cmd_tools import cmd, get_powershell_path, ps1_exec_trick
from .win_netsh import if_infos_from_netsh
from .win_iphlpapi import if_infos_from_iphlpapi, is_supported as iphlpapi_is_supported
from .win_wmic import if_infos_from_wmic


CMD_TIMEOUT = 30

IFS_PS1 = """
# Load default interface for IPv4 and IPv6.
$v4_default = Find-NetRoute -RemoteIPAddress 0.0.0.0 -erroraction 'silentlycontinue' | Format-List -Property ifIndex
$v6_default = Find-NetRoute -RemoteIPAddress :: -erroraction 'silentlycontinue' | Format-List -Property ifIndex
if($v4_default -eq $null){
    $v4_default = "null"
}
if($v6_default -eq $null){
    $v6_default = "null"
}

# Show them if any.
echo("4444444444")
echo($v4_default)
echo("4444444444")
echo("6666666666")
echo($v6_default)
echo("6666666666")

# Load interfaces and associated addresses. removed -physical
$ifs = Get-NetAdapter -erroraction 'silentlycontinue' | where status -eq up 
Foreach($iface in $ifs){
    # Get first hop for the iface for both AFs.
    $v4gw = (Get-NetRoute "0.0.0.0/0" -InterfaceIndex $iface.ifIndex  -erroraction 'silentlycontinue').NextHop 
    $v6gw = (Get-NetRoute "::/0" -InterfaceIndex $iface.ifIndex  -erroraction 'silentlycontinue').NextHop
    if($v4gw -eq $null){
        $v4gw = "null"
    }

    if($v6gw -eq $null){
        $v6gw = "null"
    }

    # Build a list of IPs with prefix lengths (e.g. "192.168.1.5/24").
    $ips = @()
    $addrs = Get-NetIPAddress -InterfaceIndex $iface.ifIndex
    Foreach($addr in $addrs){
        $ips += $addr.IPAddress + "/" + $addr.PrefixLength
    }

    # Save them as new property values.
    $iface | Add-Member -NotePropertyName v4GW -NotePropertyValue $v4gw
    $iface | Add-Member -NotePropertyName v6GW -NotePropertyValue $v6gw

    # Output this interface info with it's addresses.
    $out = $iface | Format-List -Property InterfaceDescription,ifIndex,InterfaceGuid,MacAddress,v4GW,v6GW
    echo($out)
    echo($ips)
}
"""


async def load_ifs_from_ps1():
    # Get all interface details as one big script.
    out = await asyncio.wait_for(ps1_exec_trick(IFS_PS1), 10)
    if "InterfaceDescription" not in out:
        raise Exception("Invalid powershell output for net script.")
    if "MethodNotFound" in out:
        raise Exception("Unknown error with powershell.")
    if "is not recognized as the name" in out:
        raise Exception("Powershell doesn't support these features.")

    # Load default interface by if_index.
    default_ifs = {IP4: None, IP6: None}
    if_defaults_by_index = {}
    for v in [4, 6]:
        # No to AF.
        af = v_to_af(v)

        # Regex to extract the interface no for the AF.
        delim = str(v) * 10
        p = fstr(
            r"{0}[\s\S]*ifIndex\s*:\s*([0-9]+)[\s\S]*{1}",
            (
                delim,
                delim,
            ),
        )
        if_index = re.findall(p, out)

        # Save it in a loopup table.
        if len(if_index):
            if_index = to_n(if_index[0])

            # Save it by AF.
            default_ifs[af] = if_index

            # Make a list to store AF by if_index.
            if if_index not in if_defaults_by_index:
                if_defaults_by_index[if_index] = []

            # Save AF by if_index.
            if_defaults_by_index[if_index].append(af)

    # Extract interface details.
    p = r"InterfaceDescription *: *([^\r\n]+?) *[\r\n]+ifIndex *: *([0-9]+?) *[\r\n]+InterfaceGuid *: *([^\r\n]+?) *[\r\n]+MacAddress *: *([^\r\n]+?) *[\r\n]+v4GW *: *([^\r\n]+?) *[\r\n]+v6GW *: *([^ ]+?)[\s]+((?:[0-9a-f.:%/]+ *[\r\n]*)+)"
    re_results = re.findall(p, out)

    # Index the results into a dict.
    if_infos = []
    if len(re_results):
        for r in re_results:
            if_index = to_n(r[1])
            if_info = {
                "guid": r[2],
                "name": r[0],
                "no": if_index,
                "mac": r[3],
                # Placeholders.
                "addr": None,
                "gws": {
                    IP4: None if r[4] == "null" else r[4],
                    IP6: None if r[5] == "null" else r[5],
                },
                "defaults": [],
            }

            # Set defaults.
            if if_index in if_defaults_by_index:
                if_info["defaults"] = if_defaults_by_index[if_index]

            # Process address info.
            addr_info = {IP4: [], IP6: []}
            addr_s = r[6].replace(" ", "")
            addr_list = addr_s.splitlines(False)
            for addr in addr_list:
                # Skip blank entries.
                if addr == "":
                    continue

                # Extract prefix length from "ip/prefix" format added by the PS1 script.
                prefix_len = None
                if "/" in addr:
                    raw_ip, raw_prefix = addr.rsplit("/", 1)
                    try:
                        prefix_len = int(raw_prefix)
                    except ValueError:
                        pass
                    addr = raw_ip

                addr = ip_strip_cidr(ip_strip_if(addr))
                ipr = IPRange(addr)
                host_limit = prefix_len if prefix_len is not None else af_bitlen(ipr.af)
                addr_info[ipr.af].append(
                    {
                        "addr": addr,
                        "af": ipr.af,
                        "host_limit": host_limit,
                        "netmask": cidr_to_netmask(host_limit, ipr.af),
                    }
                )

            # Save addresses.
            if_info["addr"] = addr_info

            # Save info.
            if_infos.append(if_info)

    """
    If no route found for a given address family set the first
    interface as the default interface for that AF.
    """
    for af in VALID_AFS:
        if default_ifs[af] is None:
            if len(if_infos):
                if if_infos[0]["gws"][af] is not None:
                    if_infos[0]["defaults"].append(af)

    return if_infos


async def get_default_gw_by_if_index(af, if_index):
    dest_ip = "0.0.0.0/0" if af == IP4 else "::/0"
    cmd_str = '{} "(Get-NetRoute {} -InterfaceIndex {}).NextHop"'
    cmd_str = cmd_str.format("powershell", dest_ip, if_index)

    # Execute the command.
    try:
        out = await cmd(cmd_str, timeout=CMD_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return None

    if out is None:
        return None

    # Return the string if it's a valid IP.
    out = out.strip()
    try:
        ip_f(out)
        return out
    except ValueError:
        log(out)
        return None


async def get_addr_info_by_if_index(if_index):
    addr = {IP4: [], IP6: []}
    cmd_str = 'powershell "Get-NetIPAddress -InterfaceIndex {}"'
    cmd_str = cmd_str.format(if_index)
    try:
        out = await cmd(cmd_str, timeout=CMD_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return addr

    try:
        addr_infos = re.findall(
            r"IPAddress\s*:\s*([^\s]*)[\s\S]*?AddressFamily\s*:\s*([^\s]+)[\s\S]*?PrefixLength\s*:\s([0-9]+)",
            out,
        )

        for addr_info in addr_infos:
            ip_val, af_family, host_limit = addr_info
            host_limit = int(host_limit)
            if af_family == "IPv4":
                af = IP4
            if af_family == "IPv6":
                af = IP6

            addr[af].append(
                {
                    "addr": ip_val,
                    "af": af,
                    "host_limit": host_limit,
                    "netmask": cidr_to_netmask(host_limit, af),
                }
            )
    except (ValueError, re.error):
        log_exception()
        return addr

    return addr


async def get_default_iface_by_af(af):
    if af == IP4:
        any_offset = 0
    if af == IP6:
        any_offset = 1

    any_addr_list = ["0.0.0.0", "::"]
    dest_ip = any_addr_list[any_offset]
    cmd_buf = 'powershell "Find-NetRoute -RemoteIPAddress {}"'
    cmd_buf = cmd_buf.format(dest_ip)
    try:
        out = await cmd(cmd_buf, timeout=CMD_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return None

    try:
        if_index_str = re.findall(r"InterfaceIndex\s*:\s*([0-9]+)", out)
        if len(if_index_str):
            return int(if_index_str[0])
        else:
            # If an AF is not support an error is thrown
            # and the pattern above won't match anything.
            return None
    except (ValueError, re.error):
        log_exception()
        return None


def extract_if_fields(ifs_str):
    """Returns a list of interface field dicts parsed from powershell Get-NetAdapter output."""
    results = []
    try:
        if_info_matches = re.findall(
            r"InterfaceDescription\s*:\s([^\r\n]*?)[\r\n]+ifIndex\s*:\s*([0-9]+)\s*InterfaceGuid\s*:\s*([^\r\n]+)\s*MacAddress\s*:\s*([^\s]+)\s*",
            ifs_str,
        )  # noqa
        if len(if_info_matches):
            for if_info_match in if_info_matches:
                if_desc, if_index, guid, mac_addr = if_info_match
                if_index = int(if_index)
                results.append(
                    {
                        "guid": guid,
                        "name": if_desc,
                        "no": if_index,
                        "mac": mac_addr,
                        # Placeholders.
                        "addr": None,
                        "gws": {IP4: None, IP6: None},
                        "defaults": None,
                    }
                )
    except (ValueError, re.error, AttributeError):
        log_exception()
        return results

    return results


# Get list of net adaptors via powershell.
# Ignore hidden adapters. Non-physical or down.
# Specify desc and index to show full entry.
async def get_ifaces():
    ps_path = get_powershell_path()
    try:
        out = await asyncio.wait_for(
            cmd(
                fstr(
                    '{0} "Get-NetAdapter -physical | where status -eq up  | Format-List -Property InterfaceDescription,ifIndex,InterfaceGuid,MacAddress"',
                    (ps_path,),
                )
            ),
            CMD_TIMEOUT,
        )
        if "InterfaceDescription" not in out:
            raise Exception("Get net adapter error.")
    except (OSError, asyncio.TimeoutError):
        log_exception()
        out = ""

    return out


async def win_load_interface_state(if_results):
    # Lookup whether an1
    if_defaults_by_index = {}
    af_index = {}

    async def set_ip4_if_index():
        af_index[IP4] = await get_default_iface_by_af(IP4)

    async def set_ip6_if_index():
        af_index[IP6] = await get_default_iface_by_af(IP6)

    # Execute the above functions.
    tasks = [
        set_ip4_if_index(),
        set_ip6_if_index(),
    ]
    for task in tasks:
        await task

    # Set the AFs the interface is the default for.
    if af_index[IP4] or af_index[IP6]:
        if af_index[IP4]:
            if_defaults_by_index[af_index[IP4]] = [IP4]

        if af_index[IP6]:
            if_defaults_by_index[af_index[IP6]] = [IP6]

        if af_index[IP4] == af_index[IP6]:
            if_defaults_by_index[af_index[IP4]] = [IP4, IP6]

    # Parse output lines from Get-Adapter.
    if_tasks = []
    by_guid_index = {}
    for result in if_results:

        async def if_task_func():
            try:
                if_index = result["no"]
                guid = result["guid"]

                # Default interface for these address families.
                default_for_afs = []
                if if_index in if_defaults_by_index:
                    default_for_afs = if_defaults_by_index[if_index]

                result["defaults"] = default_for_afs

                # Otherwise it's worth saving.
                by_guid_index[guid] = result

                # Get address information.
                async def set_addr():
                    by_guid_index[guid]["addr"] = await get_addr_info_by_if_index(
                        if_index
                    )

                # Get default gateways.
                async def set_ip4_gw():
                    by_guid_index[guid]["gws"][IP4] = await get_default_gw_by_if_index(
                        IP4, if_index
                    )

                async def set_ip6_gw():
                    by_guid_index[guid]["gws"][IP6] = await get_default_gw_by_if_index(
                        IP6, if_index
                    )

                # Execute the above tasks.
                sub_tasks = [set_addr(), set_ip4_gw(), set_ip6_gw()]
                for task in sub_tasks:
                    await task
            except (OSError, asyncio.TimeoutError):
                log_exception()
                return

        if_tasks.append(if_task_func())

    for if_task in if_tasks:
        await if_task

    return by_guid_index


def win_set_gateways(by_guid_index):
    """Returns a netifaces-style gateways dict built from the given GUID-indexed interface data.

    Every NIC that has a configured gateway is listed in ``gws[af]`` regardless
    of whether it is the OS-selected default route. ``gws["default"][af]`` is
    populated only for the NIC the OS picked. The previous version only
    listed NICs that won the default-route slot, which on multi-NIC hosts
    (e.g. a LAN NIC + a mobile NIC) hid working gateways from ``is_nic_default``
    and any caller asking "does this NIC have a gateway?".
    """
    gws = {"default": {}, int(IP4): [], int(IP6): []}

    for _, addr_info in by_guid_index.items():
        addrs = addr_info.get("addr") or {}
        for af in (IP4, IP6):
            gw = addr_info["gws"].get(af)
            # Empty string / None / missing entry == no gateway.
            if not gw:
                # NIC has at least one IP for this AF but no gateway --
                # surfaced loudly because we hit it on Windows XP where
                # ipconfig /all + ping confirmed a working gateway but
                # the introspection API returned blank.  Don't raise --
                # downstream code deals with missing gateways already --
                # but log so the condition is visible.
                if addrs.get(af):
                    log(fstr(
                        "blank gateway -- may be a bug: nic={0} af={1} has IP(s) but no gateway",
                        (addr_info.get("name", "?"), af),
                    ))
                continue

            is_default = af in addr_info["defaults"]
            gws[int(af)].append((gw, addr_info["name"], is_default))

            if is_default:
                gws["default"][int(af)] = (gw, addr_info["name"])

    return gws


class Netifaces:
    """Drop-in Windows replacement for the netifaces module backed by powershell, WMIC, or netsh."""

    AF_INET = IP4
    AF_INET6 = IP6
    AF_LINK = 18

    def __init__(self):
        pass

    async def start(self):
        # Per-version loader capability matrix. Don't invoke backends on
        # Windows versions where they can't work or are known to hang;
        # each fallback carries a real wall-clock cost (CMD_TIMEOUT per
        # subprocess loader = 30 s). Mapping below -- platform.version()
        # returns the NT kernel version, not the marketing version:
        #
        #   NT ver   Marketing               iphlpapi  PS1   WMIC   netsh
        #   5.0      Win 2000 / Server 2000     no      no    no    weak
        #   5.1+     Win XP SP1+                yes     no    yes   yes
        #   5.2      Server 2003                yes     no    yes   yes
        #   6.0      Vista / Server 2008        yes     no    yes   yes
        #   6.1      Win 7 / Server 2008 R2     yes     no    yes   yes
        #   6.2      Win 8 / Server 2012        yes     yes   yes   yes
        #   6.3      Win 8.1 / Server 2012 R2   yes     yes   yes   yes
        #  10.0      Win 10 / 11 / Server 2016+ yes     yes   yes*  yes
        #
        #   iphlpapi.GetAdaptersAddresses     -- XP SP1+. Single ctypes
        #     call, no subprocess. The only loader that surfaces XP's
        #     per-AF v6_no (TCPIP6 has its own ifindex space). We still
        #     guard with iphlpapi_is_supported() in case some locked-
        #     down build can't load the DLL.
        #
        #   PowerShell Get-NetAdapter (NetAdapter module) -- Win 8 / NT
        #     6.2 and later. Doesn't exist on Win 7 / Vista / XP, so the
        #     PS1 loader is gated on NT >= 6.2.
        #
        #   WMIC -- present XP+ but problematic on XP (single-threaded
        #     repository, hangs on contention) and deprecated in Win 11
        #     22H2+ where Microsoft started removing the binary by
        #     default. Skip on XP entirely (iphlpapi covers it); on
        #     newer Windows we keep WMIC as a fallback even though it
        #     may eventually be absent on a stripped-down 11/Server.
        #
        #   netsh -- weak on Win 2000 (some interface verbs missing) and
        #     on XP its IPv4 subcommands depend on a routing service that
        #     ships disabled in some installs. Reliable Vista+. Same
        #     reasoning as WMIC: skip on XP since iphlpapi suffices.
        #
        # Net effect on the matrix:
        #   XP         -> iphlpapi only (one ctypes call, ms-scale)
        #   Vista / 7  -> iphlpapi -> WMIC -> netsh
        #   Win 8 / 8.1 / 10 / 11 / Server 2012+ -> iphlpapi -> PS1 -> WMIC -> netsh
        # Win 2000 sits in the gap (no iphlpapi guarantee, no PS1, weak
        # netsh, no WMIC); we rely on iphlpapi_is_supported() returning
        # False on that ancient OS so we surface a clean failure rather
        # than running shell loaders that won't produce useful output.
        vmaj, vmin, vpatch = [int(x) for x in platform.version().split(".")]

        # Per-loader availability, computed independently from the NT
        # version so each can be reasoned about (and fixed) in
        # isolation. Names map to the kernel version, not marketing.
        nt = (vmaj, vmin)

        # iphlpapi.GetAdaptersAddresses: XP SP1 (NT 5.1+) onwards.
        # We still call iphlpapi_is_supported() because some locked-
        # down installs strip the function; the dynamic check is
        # the source of truth.
        iphlpapi_ok = nt >= (5, 1) and iphlpapi_is_supported()

        # PowerShell NetAdapter cmdlets (Get-NetAdapter): introduced
        # in Win 8 / Server 2012 (NT 6.2). Win 7 / Vista / XP do not
        # ship this module.
        ps1_ok = nt >= (6, 2)

        # WMIC: present XP+ but the XP repository hangs under
        # contention long enough to chew the CMD_TIMEOUT budget;
        # iphlpapi already covers XP, so don't fall back here.
        # Vista / 7 / 8 / 8.1 / 10 / 11 / Server 2012-2022 are fine.
        # Win 11 22H2+ (build >= 22621) ship without WMIC by
        # default; we still try because WMIC may have been re-
        # added by an admin, and the loader fails fast when the
        # binary is absent.
        wmic_ok = nt >= (6, 0)

        # netsh: works since NT 5.1 in principle but the XP "interface
        # ipv4" verbs depend on the Routing and Remote Access service
        # which is disabled by default on workstation SKUs. Skipping on
        # XP avoids the timeout cost. Vista+ runs reliably.
        netsh_ok = nt >= (6, 0)

        vectors = []
        if iphlpapi_ok:
            vectors.append(if_infos_from_iphlpapi)
        if ps1_ok:
            vectors.append(load_ifs_from_ps1)
        if wmic_ok:
            vectors.append(if_infos_from_wmic)
        if netsh_ok:
            vectors.append(if_infos_from_netsh)

        log("[NETIFACES-LOAD] nt={0}.{1} iphlpapi={2} ps1={3} wmic={4} netsh={5}".format(
            vmaj, vmin, iphlpapi_ok, ps1_ok, wmic_ok, netsh_ok,
        ))

        # Try different funcs to load IF info.
        # Retry up to 3 times with backoff: Windows drops shell calls when
        # multiple processes query interfaces simultaneously under parallel load.
        if_infos = []
        for load_attempt in range(3):
            for load_if_info in vectors:
                try:
                    if_infos = await asyncio.wait_for(load_if_info(), CMD_TIMEOUT)
                    if not len(if_infos):
                        continue

                    break
                except (OSError, asyncio.TimeoutError):
                    log_exception()

            if if_infos:
                break

            if load_attempt < 2:
                await asyncio.sleep(2 + load_attempt * 2)

        self.by_guid_index = {}
        for if_info in if_infos:
            self.by_guid_index[if_info["guid"]] = if_info

        # Sanity check.
        if self.by_guid_index == {}:
            raise Exception("Unable to load interfaces.")

        # Setup name index.
        self.by_name_index = {}
        name_counts = {}
        for _, if_info in self.by_guid_index.items():
            # Name used for this interface.
            name = if_info["name"]

            # A duplicate for this if exists.
            if name in name_counts:
                # Increment count for this name.
                name_counts[name] += 1
                count = name_counts[name]

                # Update the name associated with if details.
                name = fstr(
                    "{0} #{1}",
                    (
                        name,
                        count,
                    ),
                )
                if_info["name"] = name
            else:
                # Record first use of this name.
                name_counts[name] = 1

            # Every if_info has a unique name.
            # Because if descriptions aren't unique for the same HW.
            self.by_name_index[name] = if_info

            # Also accept lookups by adapter description (the long
            # driver string like "Intel(R) 82574L Gigabit Network
            # Connection") when the iphlpapi loader surfaces it.
            # WMIC used to return the description string as the
            # "name", so callers passing --nic with the description
            # form continue to match after the switch to iphlpapi-as-
            # primary loader. Skip when description is empty, equals
            # the friendly name, or is already a registered key.
            description = if_info.get("description")
            if description and description != name and description not in self.by_name_index:
                self.by_name_index[description] = if_info

        # Save main gateways used.
        self.gws = win_set_gateways(self.by_guid_index)
        return self

    def gateways(self):
        """Returns the netifaces-style gateways dict for all detected interfaces."""
        return self.gws

    def if_info(self, if_name):
        """Returns the full interface info dict for the given interface name."""
        return self.by_name_index[if_name]

    def guid(self, if_name):
        """Returns the GUID string for the given interface name."""
        if_info = self.if_info(if_name)
        return if_info["guid"]

    def nic_no(self, if_name):
        """Returns the integer interface index for the given interface name."""
        if_info = self.if_info(if_name)
        return if_info["no"]

    def get_nic_id(self, af, if_name):
        """Return the kernel-level interface index for if_name appropriate to af.

        af=None or IP4 -> the v4 ifindex (same as nic_no).
        af=IP6 -> the v6 ifindex; differs from the v4 ifindex on XP
        where TCPIP and TCPIP6 are separate services with separate
        index spaces. Vista+ unified the stacks so both indices match.
        Loaders that didn't capture the v6 index separately (netsh,
        wmic, ps1, win_net) fall back to the single "no" value.
        """
        if_info = self.if_info(if_name)
        if af == IP6:
            return if_info.get("v6_no") or if_info["no"]
        return if_info["no"]

    def ifaddresses(self, if_name):
        """Returns a netifaces-style address dict keyed by address family for the given interface."""
        if_info = self.by_name_index[if_name]
        addr_format = {
            int(IP4): [],
            int(IP6): [],
            # Netifaces AF_LINK = MAC address.
            Netifaces.AF_LINK: [{"addr": if_info["mac"]}],
        }

        # Add addresses in netiface format.
        for af in [IP4, IP6]:
            for addr_info in if_info["addr"][af]:
                addr = {
                    "addr": addr_info["addr"],
                    "netmask": cidr_to_netmask(addr_info["host_limit"], af),
                }

                addr_format[int(af)].append(addr)

        return addr_format

    def interfaces(self):
        """Returns a sorted list of all detected interface names.

        ONE entry per physical NIC.  The dual-name indexing (friendly
        name AND adapter description) only applies to lookup -- see
        by_name_index registration at the top of __init__ -- because
        we want --nic to match either string.  Enumeration must NOT
        emit both, otherwise load_interfaces() instantiates a fresh
        Interface and runs the full NAT-LOAD pipeline on the SAME
        physical NIC twice, costing 4-10 s of startup on every
        Windows host with adapters whose friendly name differs from
        their description (i.e. all of them on modern Windows).

        Canonical name is the friendly name when present, falling
        back to description.  This matches what the user typed in
        Network Connections and what historical warpgate code expected.
        """
        ifs = []
        seen = set()
        for _, if_info in self.by_guid_index.items():
            canonical = if_info.get("name") or if_info.get("description")
            if canonical and canonical not in seen:
                ifs.append(canonical)
                seen.add(canonical)

        ifs = sorted(ifs)
        return ifs


async def workspace():
    netifaces = Netifaces()
    await netifaces.start()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(workspace())
