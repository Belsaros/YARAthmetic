"""Bitcoin-alphabet Base58 and Base58Check reference validation.

Unlike Bitcoin Core's user-input parser, these functions accept no whitespace.
"""

from hashlib import sha256


CHARSET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def decode_base58(value: str) -> bytes:
    """Decode a strict Base58 string, preserving leading zero bytes.

    The empty string encodes empty bytes. Invalid characters raise ValueError.
    """
    number = 0
    for char in value:
        if char not in CHARSET:
            raise ValueError("invalid Base58 character")
        number = number * 58 + CHARSET.index(char)

    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + number.to_bytes(
        (number.bit_length() + 7) // 8, "big"
    )


def validate_base58check(value: str) -> bool:
    """Validate the four-byte double-SHA256 checksum, without address policy.

    No version, network, or payload-length restrictions are imposed. A valid
    checksum does not imply a valid cryptocurrency address or private key.
    """
    try:
        decoded = decode_base58(value)
    except ValueError:
        return False
    if len(decoded) < 4:
        return False
    payload, checksum = decoded[:-4], decoded[-4:]
    return sha256(sha256(payload).digest()).digest()[:4] == checksum
