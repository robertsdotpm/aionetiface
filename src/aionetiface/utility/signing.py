"""ECDSA key-pair generation, signing, and verification helpers."""
from ecdsa import SECP256k1, SigningKey, util
from .utils import to_hs


class Signing:
    """ECDSA key-pair wrapper that exposes compact public-key bytes and hex."""

    def __init__(
        self,
        priv=None,
        pub=None,
        curve=SECP256k1,
    ):
        """Wrap an existing private/public key pair on the given curve."""
        self.curve = curve
        self.private_key = priv
        self.public_key = pub or priv.get_verifying_key()
        self.compact_public_key = self.public_key.to_string("compressed")
        self.public_key_hex = to_hs(self.compact_public_key)

    @staticmethod
    def keypair(curve=SECP256k1):
        """Generate a fresh key-pair on curve and return a Signing instance."""
        priv = SigningKey.generate(curve=curve)
        pub = priv.get_verifying_key()
        return Signing(priv, pub, curve)


if __name__ == "__main__":
    kp = Signing.keypair()

    msg = b"my test msg."
    sig = kp.private_key.sign(msg, sigencode=util.sigencode_string)
