from yara_support import OUTPUT_VERSION, compiled_options

from hashlib import sha256
import random
import subprocess

import pytest

from yarithmetic.generators.base58 import (
    generate_base58check_p2pkh_rule,
    generate_base58check_p2pkh_parameterized_rule,
)
from yarithmetic.generators.compatibility import parse_output_version
from yarithmetic.reference.base58 import CHARSET, validate_base58check

pytestmark = pytest.mark.base58
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


@pytest.fixture(scope="module", params=[1, 2, "runtime"])
def compiled_rule(request, tmp_path_factory):
    root = tmp_path_factory.mktemp(f"base58check-slot{request.param}")
    rule = root / "base58check.yar"
    compiled = root / "base58check.yarc"
    runtime = request.param == "runtime"
    target = parse_output_version(OUTPUT_VERSION)
    if runtime and target is not None and target < (3, 5, 0):
        pytest.skip("runtime candidate selection requires YARA >= 3.5")
    rule.write_text(generate_base58check_p2pkh_parameterized_rule(output_version=OUTPUT_VERSION) if runtime
                    else generate_base58check_p2pkh_rule(request.param, output_version=OUTPUT_VERSION))
    externals = ["-d", "candidate_index=1"] if runtime else []
    result = subprocess.run(["yarac", *externals, str(rule), str(compiled)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return compiled, 1 if runtime else request.param, runtime


def scan(compiled_rule, tmp_path, values):
    compiled, slot, runtime = compiled_rule
    # Put non-checksummed but structurally eligible candidates before the slot
    # under test. Slots count regex occurrences, including invalid checksums.
    prefix = (GENESIS[:-1] + "b\n") * (slot - 1)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for index, value in enumerate(values):
        (corpus / str(index)).write_text(prefix + value)
    result = subprocess.run(["yara", *compiled_options(), "-r", *(["-d", f"candidate_index={slot}"] if runtime else []), str(compiled), str(corpus)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return {int(line.rsplit("/", 1)[1]) for line in result.stdout.splitlines()}


def test_real_address_and_every_single_character_mutation(compiled_rule, tmp_path):
    values = [GENESIS]
    for index, char in enumerate(GENESIS):
        replacement = CHARSET[(CHARSET.index(char) + 1) % 58]
        values.append(GENESIS[:index] + replacement + GENESIS[index + 1:])
    assert scan(compiled_rule, tmp_path, values) == {0}


def test_generated_addresses_differentially(compiled_rule, tmp_path):
    rng = random.Random(58)
    values = []
    while len(values) < 24:
        payload = b"\0" + rng.randbytes(20)
        raw = payload + sha256(sha256(payload).digest()).digest()[:4]
        number = int.from_bytes(raw, "big")
        encoded = ""
        while number:
            number, digit = divmod(number, 58)
            encoded = CHARSET[digit] + encoded
        value = "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded
        if len(value) == 34 and value[1] != "1":
            values.extend([value, value[:-1] + CHARSET[(CHARSET.index(value[-1]) + 1) % 58]])
    expected = {index for index, value in enumerate(values) if validate_base58check(value)}
    assert expected == set(range(0, 24, 2))
    assert scan(compiled_rule, tmp_path, values) == expected


def test_boundaries_missing_candidates_and_slot_limit(compiled_rule, tmp_path):
    values = [
        GENESIS, "\n" + GENESIS + "\n", "no address",
        "z" + GENESIS, GENESIS + "z", "0" + GENESIS, GENESIS + "O",
        GENESIS[:-1], "1111111111111111111114oLvT2",  # Valid but unsupported shape.
        GENESIS[:-1] + "b\n" + GENESIS,  # Later valid occurrence is outside selected slot.
    ]
    assert scan(compiled_rule, tmp_path, values) == {0, 1}


@pytest.mark.parametrize("slot", [0, 17])
def test_rejects_invalid_candidate_slot(slot):
    with pytest.raises(ValueError):
        generate_base58check_p2pkh_rule(slot)


def test_runtime_selection_reuses_compiled_circuit(compiled_rule, tmp_path):
    compiled, _, runtime = compiled_rule
    if not runtime:
        pytest.skip("runtime external applies to parameterized generator")
    invalid = GENESIS[:-1] + "b"
    sample = tmp_path / "sample"
    # Embedded matches still count; only the selected occurrence is validated.
    sample.write_text("z" + GENESIS + "\n" + invalid + "\n" + GENESIS)
    for slot in [-1, 0, 1, 2, 3, 4, 17]:
        result = subprocess.run(
            ["yara", *compiled_options(), "-d", f"candidate_index={slot}", str(compiled), str(sample)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        assert bool(result.stdout) == (slot == 3)
    # Runtime selection is not limited to the fixed generator's sixteen slots.
    sample.write_text((invalid + "\n") * 16 + GENESIS)
    result = subprocess.run(
        ["yara", *compiled_options(), "-d", "candidate_index=17", str(compiled), str(sample)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "Valid_Base58Check_P2PKH_34_Parameterized" in result.stdout
