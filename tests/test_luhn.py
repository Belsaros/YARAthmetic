import json
import pytest
from yarithmetic.reference.luhn import validate_luhn16
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "luhn16.json"

@pytest.mark.parametrize(
    "value",
    [
        "",
        "411111111111111",
        "41111111111111111",
        "411111111111111x",
        "４１１１１１１１１１１１１１１１",
    ],
)
def test_reference_luhn_rejects_malformed_input(value):
    assert validate_luhn16(value) is False

def load_vectors():
    with VECTORS.open(encoding="utf-8") as fh:
        return json.load(fh)["vectors"]


def test_luhn_vectors_exist():
    vectors = load_vectors()

    assert vectors
    assert any(v["valid"] for v in vectors)
    assert any(not v["valid"] for v in vectors)


def test_luhn_vectors_are_16_digits():
    for vector in load_vectors():
        value = vector["value"]

        assert len(value) == 16
        assert value.isascii()
        assert value.isdigit()

def test_reference_luhn_vectors():
    for vector in load_vectors():
        assert validate_luhn16(vector["value"]) is vector["valid"]
