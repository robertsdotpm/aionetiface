"""JSON keystore for PNP identities.

A keystore entry is one JSON file at ``~/aionetiface/<pnp_name>.json``
holding the ECDSA priv key plus the metadata needed to refresh the
PNP record on next startup (registered TLD, server list, registration
timestamp).  One entry per PNP name; the file name *is* the name.

For demo / no-arg callers where there's no human-picked PNP name,
the caller is expected to derive a deterministic name (e.g.
``sha256(nics + node_port)[:N]``) and pass it in as ``pnp_name``.

Format::

    {
      "pnp_name":      "foo",
      "tld":           ".p2p" | null,
      "priv_key_hex":  "<64 hex chars>",
      "registered_at": "2026-05-08T05:30:00Z" | null,
      "servers":       ["ovh1.p2pd.net", ...]
    }

``tld`` / ``registered_at`` / ``servers`` are populated by the caller
after a successful PNP put; they're left null/empty on a freshly
generated entry.
"""
from typing import Any, List, Optional, Tuple
import json
import os
import time

from ecdsa import SigningKey, SECP256k1

from .utility.fstr import fstr


KEYSTORE_DIR = os.path.expanduser(os.path.join("~", "aionetiface"))


class KeystoreEntry(object):
    """In-memory representation of one keystore JSON file."""

    def __init__(self, pnp_name, sk, tld=None, registered_at=None, servers=None):
        self.pnp_name = pnp_name
        self.sk = sk
        self.tld = tld
        self.registered_at = registered_at
        self.servers = list(servers) if servers else []


def keystore_path(pnp_name):
    """Return the JSON file path for a given PNP name."""
    if not pnp_name or not isinstance(pnp_name, str):
        raise ValueError(fstr("pnp_name must be a non-empty str, got {0}", (repr(pnp_name),)))
    if os.sep in pnp_name or "/" in pnp_name or pnp_name.startswith("."):
        raise ValueError(fstr("pnp_name {0} contains path separator or dotfile prefix", (repr(pnp_name),)))
    return os.path.join(KEYSTORE_DIR, pnp_name + ".json")


def load_or_create(pnp_name):
    """Load the keystore entry for pnp_name; generate a fresh entry on first call.

    Returns ``(entry, is_fresh)``.  ``is_fresh=True`` means the priv
    key was just generated (no prior file existed) -- callers use
    this signal to decide whether to run a first-time PNP collision
    check vs treat the registration as a refresh of a name we already
    own.
    """
    os.makedirs(KEYSTORE_DIR, exist_ok=True)
    path = keystore_path(pnp_name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        sk = SigningKey.from_string(bytes.fromhex(data["priv_key_hex"]), curve=SECP256k1)
        entry = KeystoreEntry(
            pnp_name=data.get("pnp_name", pnp_name),
            sk=sk,
            tld=data.get("tld"),
            registered_at=data.get("registered_at"),
            servers=data.get("servers", []),
        )
        return entry, False

    sk = SigningKey.generate(curve=SECP256k1)
    entry = KeystoreEntry(pnp_name=pnp_name, sk=sk)
    save(entry)
    return entry, True


def save(entry):
    """Write the keystore entry to disk, overwriting any prior contents."""
    os.makedirs(KEYSTORE_DIR, exist_ok=True)
    path = keystore_path(entry.pnp_name)
    data = {
        "pnp_name": entry.pnp_name,
        "tld": entry.tld,
        "priv_key_hex": entry.sk.to_string().hex(),
        "registered_at": entry.registered_at,
        "servers": list(entry.servers or []),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, sort_keys=True)
    os.replace(tmp, path)


def mark_registered(entry, tld, servers):
    """Update the entry with TLD + server list after a successful PNP put,
    stamp registered_at to current UTC, and persist."""
    entry.tld = tld
    entry.servers = list(servers or [])
    entry.registered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save(entry)
