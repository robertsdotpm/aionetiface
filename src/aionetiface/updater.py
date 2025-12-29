from .servers import INFRA, INFRA_BUF
from .net.address import Address
from .protocol.http.http_client_lib import WebCurl
from .install import *

async def update_server_list(nic, sys_clock=time, init_infra_buf=INFRA_BUF, init_infra=INFRA):
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
            with open(servers_path, 'r') as fp:
                stored_json = fp.read()
                stored_infra = json.loads(stored_json)

            # If the stored server list is more recent -- use that instead.
            if stored_infra:
                if stored_infra["timestamp"] > infra["timestamp"]:
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
            if "timestamp" in infra:
                infra_buf = resp_buf
                infra = resp_infra
                update_req = True
        except Exception:
            log("Cannot fetch new server list.")
            log_exception()

    # Save server list if none exists.
    if not os.path.exists(servers_path):
        update_req = True

    # Update the saved server file.
    # Only update it if needed.
    if update_req:
        if os.path.exists(servers_path):
            os.remove(servers_path)
        with open(servers_path, 'w', encoding='utf-8') as fp:
            fp.write(infra_buf)

    # Can then be used to update env variables.
    return update_req, infra_buf, infra