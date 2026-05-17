"""Local NAT-classification cache keyed on a network fingerprint.

NAT type + port-delta is a stable property of the network a host is
attached to -- it changes only when the host moves networks or the
router's behaviour shifts. Classifying it costs ~2s of STUN probing on
every node start.

This module lets a node skip that probe when it can cheaply prove it is
on the same network as a previous run: it fingerprints the current
network (interface names + local addressing + default gateways) and
looks the NAT result up in a small JSON file in the user's home dir.

A fingerprint match is a HINT, not proof. A wrong cached NAT makes a
boundary punch fire at the wrong predicted ports, so the caller MUST
still re-classify in the background and overwrite a stale entry -- the
revalidation is mandatory, not optional. The fingerprint only has to be
good enough that a genuine network change reliably misses; an occasional
false hit is corrected by the background revalidate.
"""
import hashlib
import json
import os

from ...utility.utils import log, log_exception, fstr


# One small JSON object in the user's home dir:
#   { fingerprint_hex: { nic_name: nat_dict, ... }, ... }
NAT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".aionetiface_nat_cache.json"
)

# Cap on remembered networks so the file cannot grow without bound.
NAT_CACHE_MAX_NETWORKS = 16


def gateway_ips(nic):
    """Return a sorted, de-duplicated list of default-gateway IP strings for a NIC."""
    out = []
    try:
        gws = nic.netifaces.gateways()
    except Exception:  # pylint: disable=broad-except
        return out
    if not isinstance(gws, dict):
        return out
    for af_key in list(gws.keys()):
        if af_key == "default":
            continue
        entries = gws.get(af_key)
        if not isinstance(entries, (list, tuple)):
            continue
        for entry in entries:
            # netifaces gateway entries look like (addr, ifname[, is_default]).
            if entry and isinstance(entry, (list, tuple)):
                out.append(str(entry[0]))
    return sorted(set(out))


def network_fingerprint(ifs):
    """Return a stable hex string identifying the network `ifs` are attached to.

    Built from each interface's name, its primary IPv4/IPv6 address and
    the default gateway IPs it sees. Same LAN -> same fingerprint;
    moving networks changes the gateway and/or local addressing and so
    changes the fingerprint. A hint for the NAT cache only.
    """
    from ...net.net_defs import IP4, IP6

    parts = []
    for nic in sorted(ifs, key=lambda n: str(getattr(n, "name", ""))):
        name = str(getattr(nic, "name", ""))
        ip4 = ""
        ip6 = ""
        try:
            ip4 = str(nic.nic(IP4) or "")
        except Exception:  # pylint: disable=broad-except
            ip4 = ""
        try:
            ip6 = str(nic.nic(IP6) or "")
        except Exception:  # pylint: disable=broad-except
            ip6 = ""
        gws = ",".join(gateway_ips(nic))
        parts.append("|".join((name, ip4, ip6, gws)))
    raw = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def load_nat_cache():
    """Read the whole NAT cache file; return an empty dict on any error."""
    try:
        with open(NAT_CACHE_PATH, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        # Missing file or corrupt JSON -- treat as empty, not an error.
        pass
    except Exception:  # pylint: disable=broad-except
        log_exception()
    return {}


def nat_cache_get(fingerprint):
    """Return the cached {nic_name: nat_dict} for this fingerprint, or None."""
    entry = load_nat_cache().get(fingerprint)
    if isinstance(entry, dict) and entry:
        log(fstr("[NAT-CACHE] hit fingerprint={0}", (fingerprint[:12],)))
        return entry
    log(fstr("[NAT-CACHE] miss fingerprint={0}", (fingerprint[:12],)))
    return None


def nat_cache_put(fingerprint, nat_by_nic):
    """Store {nic_name: nat_dict} under this fingerprint (best-effort).

    Atomic write via a temp file + os.replace so a crash mid-write
    cannot leave a half-written cache for the next run to choke on.
    """
    if not fingerprint or not isinstance(nat_by_nic, dict) or not nat_by_nic:
        return
    try:
        cache = load_nat_cache()
        cache[fingerprint] = nat_by_nic
        # Bound the file: keep the most-recently-inserted networks.
        if len(cache) > NAT_CACHE_MAX_NETWORKS:
            for stale in list(cache.keys())[:-NAT_CACHE_MAX_NETWORKS]:
                del cache[stale]
        tmp_path = NAT_CACHE_PATH + ".tmp"
        with open(tmp_path, "w") as fh:
            json.dump(cache, fh)
        os.replace(tmp_path, NAT_CACHE_PATH)
        log(fstr(
            "[NAT-CACHE] stored fingerprint={0} nics={1}",
            (fingerprint[:12], len(nat_by_nic)),
        ))
    except (OSError, ValueError):
        log_exception()
    except Exception:  # pylint: disable=broad-except
        log_exception()
