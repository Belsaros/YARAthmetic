import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.bech32

from yarithmetic.reference.bech32 import (
    decode_data,
    hrp_expand,
    polymod,
    polymod_step,
    validate_bech32,
    validate_bech32m,
)

@pytest.fixture(scope="module")
def vectors():
    path = Path(__file__).parent / "vectors" / "bech32.json"

    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_valid_bech32_vectors(vectors):
    for value in vectors["bech32"]["valid"]:
        assert validate_bech32(value), value


def test_invalid_bech32_vectors(vectors):
    for value in vectors["bech32"]["invalid"]:
        assert not validate_bech32(value), value


def test_valid_bech32m_vectors(vectors):
    for value in vectors["bech32m"]["valid"]:
        assert validate_bech32m(value), value


def test_invalid_bech32m_vectors(vectors):
    for value in vectors["bech32m"]["invalid"]:
        assert not validate_bech32m(value), value


def test_bech32_and_bech32m_are_mutually_exclusive(vectors):
    values = (
        vectors["bech32"]["valid"]
        + vectors["bech32m"]["valid"]
    )

    for value in values:
        assert validate_bech32(value) != validate_bech32m(value), value

def test_polymod_step_without_generator_taps():
    assert polymod_step(1, 0) == 32

def test_polymod_step_with_generator_taps():
    checksum = 0b10101 << 25

    assert polymod_step(checksum, 7) == 0x0FDF2CFC

def test_polymod_multiple_values():
    assert polymod([0, 1, 2, 3]) == 0x00100443

def test_hrp_expand():
    assert hrp_expand("abc") == [3, 3, 3, 0, 1, 2, 3]

def test_decode_data():
    assert decode_data("qpzry9x8") == list(range(8))
    assert decode_data("l") == [31]

def test_decode_data_accepts_uppercase():
    assert decode_data("QPZRY9X8") == list(range(8))
    assert decode_data("L") == [31]

def test_rejects_structurally_invalid_values():
    assert not validate_bech32("")
    assert not validate_bech32("a1qqqqq")       # only five data characters
    assert not validate_bech32("a1QQQQQQ")      # mixed case
    assert not validate_bech32("a" * 83 + "1" + "q" * 7)  # 91 chars
