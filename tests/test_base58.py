import json
from hashlib import sha256
from pathlib import Path

import pytest

from yarithmetic.reference.base58 import CHARSET, decode_base58, validate_base58check

pytestmark = pytest.mark.base58
VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "base58.json").read_text()
)["vectors"]


@pytest.mark.parametrize("hex_value,encoded", VECTORS)
def test_decode_public_vectors(hex_value, encoded):
    assert decode_base58(encoded) == bytes.fromhex(hex_value)


@pytest.mark.parametrize("value", ["0", "O", "I", "l", "é", "１", " 2g", "2g\n", "2\x00g"])
def test_invalid_alphabet(value):
    with pytest.raises(ValueError):
        decode_base58(value)
    assert not validate_base58check(value)


def encode_check(payload):
    """Test-only inverse, independent of the decoder's multiply-and-add loop."""
    raw = payload + sha256(sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = CHARSET[digit] + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded


def test_base58check_genesis_address_and_mutations():
    # Public Bitcoin genesis block address; independently verify full bytes.
    value = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert decode_base58(value).hex() == (
        "0062e907b15cbf27d5425399ebf6f0fb50ebb88f18c29b7d93"
    )
    assert validate_base58check(value)
    for index, char in enumerate(value):
        mutated = value[:index] + CHARSET[(CHARSET.index(char) + 1) % 58] + value[index + 1:]
        assert not validate_base58check(mutated)


@pytest.mark.parametrize("payload", [b"", b"\0", bytes(21), bytes(range(21)), b"\x80" + bytes(range(32))])
def test_base58check_generated_payloads(payload):
    value = encode_check(payload)
    assert decode_base58(value)[:-4] == payload
    assert validate_base58check(value)


@pytest.mark.parametrize("value", ["", "1", "1111", "2g", "a3gV"])
def test_base58_does_not_imply_valid_checksum(value):
    assert not validate_base58check(value)
