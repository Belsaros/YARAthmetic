from yara_support import OUTPUT_VERSION

import random
import subprocess

import pytest

from yarithmetic.generators.base58 import (
    generate_base58_candidate_rule,
    generate_charset_value,
    generate_decoded_word,
)
from yarithmetic.reference.base58 import CHARSET, decode_base58

pytestmark = pytest.mark.base58


def run_rule(tmp_path, source, data):
    rule = tmp_path / "rule.yar"
    sample = tmp_path / "sample"
    rule.write_text(source)
    sample.write_bytes(data)
    result = subprocess.run(["yara", str(rule), str(sample)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return bool(result.stdout)


def test_entire_alphabet_mapping(tmp_path):
    checks = [
        f"{generate_charset_value(f'uint8({offset})')} == {offset}"
        for offset in range(58)
    ]
    assert run_rule(tmp_path, "rule Mapping { condition: " + " and ".join(checks) + " }", CHARSET.encode())


@pytest.mark.parametrize("length", [1, 5, 26, 34, 35, 51, 52, 111, 128])
def test_all_decoded_words_against_reference(tmp_path, length):
    rng = random.Random(length)
    values = [
        "1" * length,
        "z" * length,
        "1" + "z" * (length - 1),
        "".join(rng.choice(CHARSET) for _ in range(length)),
    ]
    for value in values:
        number = int.from_bytes(decode_base58(value), "big")
        word_count = ((58 ** length - 1).bit_length() + 31) // 32
        checks = [
            f"{generate_decoded_word('3', length, word)} == {hex((number >> (word * 32)) & 0xffffffff)}"
            for word in range(word_count)
        ]
        assert run_rule(tmp_path, "rule Decode { condition: " + " and ".join(checks) + " }", b"xx:" + value.encode())


@pytest.mark.parametrize("value,expected", [
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", True),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", True),  # Invalid checksum, still a candidate.
    ("z" * 25, False),
    ("z" * 26, True),
    ("z" * 35, True),
    ("z" * 36, False),
    ("0" + "z" * 26, False),
    ("z" * 26 + "O", False),
    ("I" + "z" * 26, False),
    ("z" * 26 + "l", False),
    ("z" * 15 + "0" + "z" * 15, False),
    ("\n" + "z" * 26 + "\n", True),
    ("0" + "z" * 26 + "\n" + "z" * 26, True),
])
def test_candidate_boundaries_and_lengths(tmp_path, value, expected):
    assert run_rule(tmp_path, generate_base58_candidate_rule(output_version=OUTPUT_VERSION), value.encode()) == expected


@pytest.mark.parametrize("length,word", [(0, 0), (129, 0), (34, -1), (34, 7)])
def test_decoder_rejects_unsupported_dimensions(length, word):
    with pytest.raises(ValueError):
        generate_decoded_word("0", length, word)


@pytest.mark.parametrize("minimum,maximum", [(0, 35), (35, 26), (26, 129)])
def test_candidate_rejects_unsupported_lengths(minimum, maximum):
    with pytest.raises(ValueError):
        generate_base58_candidate_rule(minimum, maximum)
