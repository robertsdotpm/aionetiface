"""JSON keystore for PNP identities.

One file per pnp_name at ``~/aionetiface/<pnp_name>.json`` holding the
ECDSA priv key.  ``load_or_create(name)`` returns the SigningKey:
loads it if the file exists, generates + saves a fresh one otherwise.
That's the entire interface.
"""
import json
import os

from ecdsa import SigningKey, SECP256k1

from .utility.fstr import fstr


KEYSTORE_DIR = os.path.expanduser(os.path.join("~", "aionetiface"))


def keystore_path(pnp_name):
    """Return the JSON file path for a given PNP name."""
    if not pnp_name or not isinstance(pnp_name, str):
        raise ValueError(fstr("pnp_name must be a non-empty str, got {0}", (repr(pnp_name),)))
    if os.sep in pnp_name or "/" in pnp_name or pnp_name.startswith("."):
        raise ValueError(fstr("pnp_name {0} contains path separator or dotfile prefix", (repr(pnp_name),)))
    return os.path.join(KEYSTORE_DIR, pnp_name + ".json")


def load_or_create(pnp_name):
    """Return the SigningKey for pnp_name, generating + persisting a fresh one on first call."""
    os.makedirs(KEYSTORE_DIR, exist_ok=True)
    path = keystore_path(pnp_name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        return SigningKey.from_string(bytes.fromhex(data["priv_key_hex"]), curve=SECP256k1)

    sk = SigningKey.generate(curve=SECP256k1)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(
            {"pnp_name": pnp_name, "priv_key_hex": sk.to_string().hex()},
            fp,
            indent=2,
            sort_keys=True,
        )
    os.replace(tmp, path)
    return sk
