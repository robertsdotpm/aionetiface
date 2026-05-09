"""Fallback netifaces implementation when the C extension is absent."""
import socket
from ...net.net_defs import AF_LINK, INTERFACE_ETHERNET, IP4, IP6, VALID_AFS


def load_if_info_fallback(nic):
    """Populate nic with best-effort interface info using raw socket probes when netifaces is unavailable."""
    # Just guess name.
    # Getting this wrong will only break IPv6 link-local binds.
    nic.id = nic.name = nic.name or "eth0"
    nic.netiface_index = 0
    nic.type = INTERFACE_ETHERNET

    # Get IP of default route.
    ips = {
        IP4: "8.8.8.8",
        IP6: "2404:6800:4015:803::200e",
    }

    # Build a table of default interface IPs based on con success.
    # Supported stack changes based on success.
    if_addrs = {}
    for af in VALID_AFS:
        try:
            s = socket.create_connection((ips[af], 80))
            if_addrs[s.family] = s.getsockname()[0][:]
            s.close()
        except OSError:
            continue

    # Same API as netifaces.
    class NetifaceShim:
        """Minimal netifaces-compatible shim backed by IP addresses discovered via socket probes."""

        def __init__(self, if_addrs):
            self.if_addrs = if_addrs

        def interfaces(self):
            """Return a list containing only this shim's interface name."""
            return [self.name]

        def ifaddresses(self, name):
            """Return a netifaces-style address dict for name, using the probed IP addresses."""
            ret = {
                # MAC address (blanket)
                # 17 = netifaces.AF_LINK enum.
                AF_LINK: [{"addr": "", "broadcast": "ff:ff:ff:ff:ff:ff"}],
            }

            for af in self.if_addrs:
                ret[af] = [{"addr": self.if_addrs[af], "netmask": "0"}]

            return ret

        def get_nic_id(self, af, name):
            """Parity with Netifaces.get_nic_id; the fallback has no
            real ifindex source so return the interface name -- the
            kernel accepts a name string in fe80::%scope on POSIX,
            and on Windows this code path only runs when the richer
            shim couldn't load anything anyway.
            """
            return self.name

    nic.netifaces = NetifaceShim(if_addrs)
    nic.is_default = nic.is_default_patch
