from yara_support import OUTPUT_VERSION, compiled_options

from hashlib import sha256
import random
import subprocess

import pytest

from yarithmetic.generators.sha256 import BooleanCircuit, digest_bytes

pytestmark = pytest.mark.base58


@pytest.mark.parametrize("length", [0, 3, 21, 32, 55])
def test_full_sha256_digest_against_hashlib(tmp_path, length):
    circuit = BooleanCircuit()
    message = [
        [circuit.input(f"((uint8({offset}) >> {bit}) & 1) == 1") for bit in range(8)]
        for offset in range(length)
    ]
    digest = digest_bytes(circuit.sha256(message))
    checks = []
    for offset, byte in enumerate(digest):
        for bit, wire in enumerate(byte):
            expected = circuit.input(f"((uint8({length + offset}) >> {bit}) & 1) == 1")
            checks.append(circuit.gate("not", circuit.gate("xor", wire, expected)))
    rule = tmp_path / "sha.yar"
    compiled = tmp_path / "sha.yarc"
    rule.write_text("".join(circuit.rules) + "rule Digest { condition: " + " and ".join(checks) + " }")
    result = subprocess.run(["yarac", str(rule), str(compiled)], capture_output=True, text=True)
    if (
        length == 55
        and OUTPUT_VERSION in ("3.4", "3.4.0", "3.5", "3.5.0")
        and "yr_arena_coalesce" in result.stderr
    ):
        pytest.xfail("YARA 3.4/3.5 compiler asserts while serializing this large SHA probe")
    assert result.returncode == 0, result.stderr
    rng = random.Random(length)
    values = [bytes(length), bytes([255]) * length, rng.randbytes(length)]
    if length == 3:
        values.append(b"abc")  # Standard public SHA-256 example.
    for message in values:
        digest = sha256(message).digest()
        sample = tmp_path / "sample"
        sample.write_bytes(message + digest)
        result = subprocess.run(["yara", *compiled_options(), str(compiled), str(sample)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert "Digest" in result.stdout
        sample.write_bytes(message + digest[:-1] + bytes([digest[-1] ^ 1]))
        result = subprocess.run(["yara", *compiled_options(), str(compiled), str(sample)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert not result.stdout


def test_sha256_rejects_multiple_blocks_and_malformed_bytes():
    with pytest.raises(ValueError):
        BooleanCircuit().sha256([["false"] * 8] * 56)
    with pytest.raises(ValueError):
        BooleanCircuit().sha256([["false"] * 7])
