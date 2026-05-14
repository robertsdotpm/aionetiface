"""Loads and normalises NIC information from the OS."""
import asyncio
import socket
from ..errors import InterfaceNotFound, InterfaceInvalidAF
from ..net.net_defs import AF_ANY, DUEL_STACK, VALID_AFS, VALID_STACKS, IP4, IP6, UDP
from ..protocol.stun.stun_defs import RFC5389
from ..utility.utils import async_wrap_errors, fstr, log, log_exception, to_s
from .route.route_pool import RoutePool
from .route.route_load import discover_nic_wan_ips
from .netifaces.netiface_fallback import load_if_info_fallback
from .netifaces.netiface_extra import get_mac_address
from .interface_utils import (
    clean_if_list,
    get_default_iface,
    get_interface_af,
    get_interface_stack,
    get_interface_type,
)
from ..protocol.stun.stun_client import get_stun_clients
from ..entrypoint import aionetiface_setup_netifaces
from .. import servers as servers_pkg
from ..servers import get_infra
from ..updater import update_server_list

INFRA = servers_pkg.INFRA
INFRA_BUF = None

_infra_lock = asyncio.Lock()


# Load mac, nic_no, and process name.
def load_if_info(nic):
    """Resolve the interface name, index, type, and NIC number from the OS and store them on nic."""
    # Assume its an AF.
    if isinstance(nic.name, int):
        if nic.name not in [IP4, IP6, AF_ANY]:
            raise InterfaceInvalidAF

        nic.name = get_default_iface(nic.netifaces, afs=[nic.name])

    # No name specified.
    # Get name of default interface.
    log(fstr("Load if info = {0}", (nic.name,)))
    if nic.name is None or nic.name == "":
        # Windows -- default interface name is a GUID.
        # This is ugly AF.
        iface_name = get_default_iface(nic.netifaces)
        iface_af = get_interface_af(nic.netifaces, iface_name)
        if iface_name is None:
            raise InterfaceNotFound
        else:
            nic.name = iface_name

        # Allow blank interface names to be used for testing.
        log(fstr("> default interface loaded = {0}", (iface_name,)))

        # May not be accurate.
        # Start() is the best way to set this.
        if nic.stack == DUEL_STACK:
            nic.stack = iface_af
            log(fstr("if load changing stack to {0}", (nic.stack,)))

    # Windows NIC descriptions are used for the name
    # if the interfaces are detected as all hex.
    # It's more user friendly.
    nic.name = to_s(nic.name)

    # Check ID exists.
    if nic.netifaces is not None:
        
        if_names = nic.netifaces.interfaces()
        if nic.name not in if_names:
            log(
                fstr(
                    "interface name {0} not in {1}",
                    (
                        nic.name,
                        if_names,
                    ),
                )
            )
            raise InterfaceNotFound
        nic.type = get_interface_type(nic.name)
        
        # nic.get_nic_id() dispatches to the netifaces backend's
        # get_nic_id(af, name) when present (Windows shim, fallback
        # shim, test shim) and otherwise falls back to nic.name --
        # the same end state the previous nic_no hasattr branch
        # produced, but with the per-backend dispatch handled in
        # one place inside Interface.
        nic.id = nic.get_nic_id()
        if isinstance(nic.id, int):
            nic.nic_no = nic.id
        else:
            try:
                nic.nic_no = socket.if_nametoindex(nic.name)
            except (OSError, AttributeError):
                nic.nic_no = 0
        nic.netiface_index = if_names.index(nic.name)

    return nic


async def load_interface(
    nic, netifaces, min_agree, max_agree, timeout
):
    """Fully resolve a NIC object by discovering its WAN IPs via STUN and setting its routes and stack type."""
    global INFRA_BUF
    global INFRA

    # Not needed.
    if nic.name == "default":
        return nic

    # Update internal server list if needed.
    # Uses time.time which may not be accurate.
    update_req, infra_buf, infra = await update_server_list(nic.__class__("default"))
    if update_req:
        async with _infra_lock:
            INFRA_BUF = infra_buf
            INFRA = infra

    stack = nic.stack
    log(fstr("Starting resolve with stack type = {0}", (stack,)))

    # Load internal interface details.
    nic.netifaces = await aionetiface_setup_netifaces()

    # Process interface name in right format.
    try:
        load_if_info(nic)
    except InterfaceNotFound:
        raise InterfaceNotFound
    except (OSError, ValueError, AttributeError):
        log_exception()
        load_if_info_fallback(nic)

    # This will be used for the routes call.
    # It's only purpose is to pass in a custom netifaces for tests.
    netifaces = netifaces or nic.netifaces

    # Get routes for AF.
    tasks = []
    for af in VALID_AFS:
        log(fstr("Attempting to resolve {0}", (af,)))

        # Initialize with blank RP.
        nic.rp[af] = RoutePool()

        # Used to resolve nic addresses.
        servers = get_infra(af, UDP, "STUN(see_ip)", max_agree + 5)
        stun_clients = get_stun_clients(af, max_agree, nic, RFC5389, servs=servers)

        assert len(stun_clients) <= max_agree

        # Is this default iface for this AF?
        try:
            if nic.is_default(af):
                enable_default = True
            else:
                enable_default = False
        except (OSError, AttributeError):
            # If it's poorly supported allow default NIC behavior.
            log_exception()
            enable_default = True
        log(
            fstr(
                "{0} {1} {2}",
                (
                    nic.name,
                    af,
                    enable_default,
                ),
            )
        )

        # Use a threshold of pub servers for res.
        tasks.append(
            async_wrap_errors(
                discover_nic_wan_ips(
                    af,
                    min_agree,
                    enable_default,
                    nic,
                    stun_clients,
                    netifaces,
                    timeout=timeout,
                )
            )
        )

    # Get all the routes concurrently.
    results = await asyncio.gather(*tasks)
    results = [r for r in results if r is not None]
    for af, routes, link_locals in results:
        nic.rp[af] = RoutePool(routes, link_locals)

    # Per-AF STUN summary so an "InterfaceNotFound" failure points at
    # the AF whose discovery failed, instead of disappearing into a
    # bare InterfaceNotFound traceback.
    for af in VALID_AFS:
        log(fstr(
            "load_interface STUN summary: nic={0} af={1} routes={2} link_locals={3}",
            (
                nic.name, af,
                len(nic.rp[af].routes) if af in nic.rp else 0,
                len(getattr(nic.rp.get(af, None), "link_locals", []) or []) if af in nic.rp else 0,
            ),
        ))

    # Update stack type based on routable.
    nic.stack = get_interface_stack(nic.rp)
    if nic.stack not in VALID_STACKS:
        log(fstr(
            "load_interface: nic={0} -> InterfaceNotFound (stack={1} not in {2})",
            (nic.name, nic.stack, VALID_STACKS),
        ))
        raise InterfaceNotFound

    nic.resolved = True

    # Set MAC address of Interface.
    nic.mac = await get_mac_address(nic.name, nic.netifaces)
    if nic.mac is None:
        # Currently not used for anything important.
        # Might as well not crash if not needed.
        log("Could not load mac. Setting to blank.")
        nic.mac = ""

    # If there's only 1 interface set is_default.
    ifs = clean_if_list(nic.netifaces.interfaces())
    if len(ifs) == 1:
        nic.is_default = nic.is_default_patch

    return nic
