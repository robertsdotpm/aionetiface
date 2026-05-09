"""Type conversion helpers: bytes/str/hex/int encoding round-trips."""
import binascii


__all__ = [
    "to_b",
    "to_s",
    "to_hs",
    "to_h",
    "to_i",
    "to_n",
    "i_to_b",
    "b_to_i",
    "h_to_b",
]


def to_b(x):
    """Convert x to bytes. Passes through if already bytes."""
    return x if isinstance(x, bytes) else x.encode("ascii", errors="ignore")


def to_s(x):
    """Convert x to str. Passes through if already str."""
    return x if isinstance(x, str) else x.decode("utf-8", errors="ignore")


# Hex string conversions.
def to_hs(x):
    """Convert bytes or str to a lowercase hex string."""
    return to_s(binascii.hexlify(to_b(x)))


def to_h(x):
    """Convert x to hex, returning '00' for empty input."""
    return to_hs(x) if len(x) else "00"


# Integer / numeric conversions.
def to_i(x):
    """Convert a hex string or int to an integer."""
    return x if isinstance(x, int) else int(x, 16)


def to_n(x):
    """Convert a decimal string or int to an integer."""
    return x if isinstance(x, int) else int(to_s(x), 10)


# Integer <-> bytes conversions.
def i_to_b(x, o="little"):
    """Encode an integer as bytes in the given byte order."""
    return x.to_bytes((x.bit_length() + 7) // 8, o)


def b_to_i(x, o="little"):
    """Decode bytes to an integer in the given byte order."""
    return int.from_bytes(x, o)


def h_to_b(x):
    """Decode a hex string to bytes."""
    return binascii.unhexlify(to_b(x))
