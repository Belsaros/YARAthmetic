from yara_support import OUTPUT_VERSION, compiled_options

"""Behavioral checks for the complete runtime-shape Bech32 generator."""

import json
from pathlib import Path
import random
import subprocess

import pytest

from yarithmetic.benchmark.corpus import encode_bech32, generate_hrp, mutate_bech32
from yarithmetic.generators.bech32 import generate_bech32_rule, generate_bech32_rule_unrolled
from yarithmetic.generators.bech32_compact import advance, generate_compact_bech32_rule, generate_lookup
from yarithmetic.reference.bech32 import BECH32_CONSTANT, BECH32M_CONSTANT, validate

pytestmark = pytest.mark.bech32


def test_committed_rule_is_current():
    rule = Path(__file__).resolve().parents[1] / "generated" / "bech32.yar"
    assert rule.read_text() == generate_bech32_rule()


@pytest.fixture(scope="module")
def compiled_rule(tmp_path_factory):
    root = tmp_path_factory.mktemp("compact-bech32")
    source = generate_bech32_rule(output_version=OUTPUT_VERSION)
    rule, compiled = root / "rule.yar", root / "rule.yarc"
    rule.write_text(source)
    result = subprocess.run(["yarac", str(rule), str(compiled)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    # Protect the shared-arithmetic design from accidental full unrolling.
    assert len(source) < 500_000
    assert compiled.stat().st_size < 500_000
    return compiled


def scan_directory(compiled, directory):
    result = subprocess.run(["yara", *compiled_options(), "-r", str(compiled), str(directory)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return {Path(line.split(" ", 1)[1]).name for line in result.stdout.splitlines()}


def test_all_3486_shapes_both_encodings_and_checksum_mutations(compiled_rule, tmp_path):
    rng = random.Random(173350)
    expected = set()
    count = 0
    for length in range(8, 91):
        for hrp_length in range(1, length - 6):
            for encoding in (BECH32_CONSTANT, BECH32M_CONSTANT):
                hrp = generate_hrp(rng, hrp_length, uppercase=count % 2 == 1)
                data = [rng.randrange(32) for _ in range(length - hrp_length - 7)]
                value = encode_bech32(hrp, data, encoding)
                assert len(value) == length
                assert validate(value, encoding)
                name = f"{length}-{hrp_length}-{encoding:x}"
                (tmp_path / name).write_text(value)
                expected.add(name)
                mutated = mutate_bech32(value)
                assert not validate(mutated, BECH32_CONSTANT)
                assert not validate(mutated, BECH32M_CONSTANT)
                (tmp_path / (name + "-bad")).write_text(mutated)
                count += 1
    assert count == 6972
    assert scan_directory(compiled_rule, tmp_path) == expected


def test_public_vectors(compiled_rule, tmp_path):
    vectors = json.loads((Path(__file__).parent / "vectors" / "bech32.json").read_text())
    expected = set()
    for encoding, groups in vectors.items():
        for validity, values in groups.items():
            for index, value in enumerate(values):
                name = f"{encoding}-{validity}-{index}"
                (tmp_path / name).write_text(value)
                if validity == "valid":
                    expected.add(name)
    assert scan_directory(compiled_rule, tmp_path) == expected


def test_later_candidates_case_boundaries_and_end_of_file(compiled_rule, tmp_path):
    valid = "A12UEL5L"
    # The valid value ends exactly at EOF. Padding arithmetic must not read
    # undefined bytes beyond it, even for the shortest possible candidate.
    values = {
        "valid-at-eof": valid,
        "late-valid": ("A12UEL5M\n" * 400) + valid,
        "two-variants": "A12UEL5M\nA1LQFN3A",
        "mixed-case": "a12UEL5L",
        "printable-prefix": "!" + valid,
        "whitespace-prefix": "text\n" + valid,
        "no-match": "ordinary input",
        "overlong": encode_bech32("a" * 84, [], BECH32_CONSTANT),
        "invalids-only": "A12UEL5M\n" * 100,
    }
    for name, value in values.items():
        (tmp_path / name).write_text(value)
    assert scan_directory(compiled_rule, tmp_path) == {
        "valid-at-eof", "late-valid", "two-variants", "whitespace-prefix"
    }


def test_shape_restrictions_agree_with_unrolled(tmp_path):
    values = ["A12UEL5L", "A1LQFN3A", "foo1bar1yfwynv", "A12UEL5M"]
    sources = [
        generate_compact_bech32_rule(shapes=[(8, 1)], output_version=OUTPUT_VERSION),
        generate_bech32_rule_unrolled(shapes=[(8, 1)], output_version=OUTPUT_VERSION),
    ]
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for index, value in enumerate(values):
        (corpus / str(index)).write_text(value)
    for index, source in enumerate(sources):
        rule, compiled = tmp_path / f"{index}.yar", tmp_path / f"{index}.yarc"
        rule.write_text(source)
        result = subprocess.run(["yarac", str(rule), str(compiled)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert scan_directory(compiled, corpus) == {"0", "1"}


def test_packed_lookup_every_index_and_transition_constants(tmp_path):
    rng = random.Random(173)
    values = [rng.randrange(1 << 30) for _ in range(128)]
    values[0] = 0
    values[-1] = (1 << 30) - 1
    lookup = generate_lookup(values, "uint8(0)")
    # Every index is evaluated at scan time, including both sides of all pair
    # boundaries and the maximum 30-bit coefficient.
    rule = tmp_path / "lookup.yar"
    rule.write_text(f"rule Lookup {{ condition: {lookup} == uint32(1) }}")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for index, expected in enumerate(values):
        (corpus / str(index)).write_bytes(bytes([index]) + expected.to_bytes(4, "little"))
        (corpus / f"bad-{index}").write_bytes(bytes([index]) + (expected ^ 1).to_bytes(4, "little"))
    result = subprocess.run(["yara", "-r", str(rule), str(corpus)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    actual = {Path(line.split(" ", 1)[1]).name for line in result.stdout.splitlines()}
    assert actual == {str(index) for index in range(128)}
    # T is invertible on 30-bit states, so no nonzero encoding constant or
    # difference between the encodings disappears during padding.
    assert all(advance(BECH32_CONSTANT ^ BECH32M_CONSTANT, distance) != 0 for distance in range(83))
