import json
import pytest
from yarithmetic.reference.luhn import validate_luhn
from pathlib import Path

pytestmark = pytest.mark.luhn

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "luhn.json"

@pytest.mark.parametrize(
    "value",
    [
        "",
        "411111111111111x",
        "４１１１１１１１１１１１１１１１",
    ],
)
def test_reference_luhn_rejects_malformed_input(value):
    assert validate_luhn(value) is False

def load_vectors():
    with VECTORS.open(encoding="utf-8") as fh:
        return json.load(fh)["vectors"]


def test_luhn_vectors_exist():
    vectors = load_vectors()

    assert vectors
    assert any(v["valid"] for v in vectors)
    assert any(not v["valid"] for v in vectors)

def test_luhn_vectors_are_ascii_digits():
    for vector in load_vectors():
        value = vector["value"]

        assert value
        assert value.isascii()
        assert value.isdigit()

def test_reference_luhn_vectors():
    for vector in load_vectors():
        assert validate_luhn(vector["value"]) is vector["valid"]
