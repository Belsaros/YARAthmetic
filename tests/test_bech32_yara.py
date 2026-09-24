import subprocess

import pytest

from yarithmetic.generators.bech32 import (
    generate_bech32_rule,
    generate_bit_mask,
    generate_charset_value,
    generate_polymod_check,
    generate_polymod_tap,
    generate_polymod_step,
    generate_symbolic_bit_expression,
    generate_symbolic_polymod,
)

from yarithmetic.reference.bech32 import (
        polymod_step as reference_polymod_step,
        polymod as reference_polymod,
)

pytestmark = pytest.mark.bech32

def test_generated_bech32_rule_matches_candidate(tmp_path):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(generate_bech32_rule(), encoding="utf-8")
    sample_path.write_text(
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        encoding="ascii",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_rejects_non_candidate(tmp_path):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(generate_bech32_rule(), encoding="utf-8")
    sample_path.write_text(
        "There is absolutely no encoded data in this file.",
        encoding="ascii",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def run_rule(tmp_path, value):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(generate_bech32_rule(), encoding="utf-8")
    sample_path.write_text(value, encoding="ascii")

    return subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

def test_generated_bech32_rule_rejects_candidate_over_90_characters(tmp_path):
    value = "a" * 83 + "1" + "q" * 7
    assert len(value) == 91

    result = run_rule(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_generated_bech32_rule_allows_90_character_candidate(tmp_path):
    value = "a" * 83 + "1" + "q" * 6
    assert len(value) == 90

    result = run_rule(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_rejects_data_part_shorter_than_checksum(tmp_path):
    value = "a1" + "q" * 5

    result = run_rule(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_bech32_rule_allows_six_character_data_part(tmp_path):
    value = "a1" + "q" * 6

    result = run_rule(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_allows_lowercase_candidate(tmp_path):
    result = run_rule(tmp_path, "a1qqqqqq")

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout


def test_generated_bech32_rule_allows_uppercase_candidate(tmp_path):
    result = run_rule(tmp_path, "A1QQQQQQ")

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout


def test_generated_bech32_rule_rejects_mixed_case_candidate(tmp_path):
    result = run_rule(tmp_path, "a1QQQQQQ")

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_bech32_rule_rejects_mixed_case_hrp(tmp_path):
    result = run_rule(tmp_path, "aB1qqqqqq")

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_bech32_rule_allows_one_in_hrp(tmp_path):
    result = run_rule(tmp_path, "foo1bar1qqqqqq")

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


@pytest.mark.parametrize(
    ("char", "expected"),
    [
        (representation, value)
        for value, char in enumerate(CHARSET)
        for representation in {char, char.upper()}
    ],
)
def test_generated_charset_value_maps_all_characters(tmp_path, char, expected):
    expression = generate_charset_value("uint8(0)")

    rule = f"""
rule Charset_Value
{{
    condition:
        {expression} == {expected}
}}
"""

    rule_path = tmp_path / "charset.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_text(char, encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Charset_Value" in result.stdout

def test_generate_bit_mask():
    assert generate_bit_mask("b", 0b10110) == (
        "((b << 1) | (b << 2) | (b << 4))"
    )

def test_generate_bit_mask_with_low_bit():
    assert generate_bit_mask("b", 0b10101) == (
        "((b) | (b << 2) | (b << 4))"
    )


def test_generate_bit_mask_with_zero_mask():
    assert generate_bit_mask("b", 0) == "0"

@pytest.mark.parametrize(
    ("input_byte", "expected"),
    [
        (0, 0),
        (1, 0b10110),
    ],
)
def test_generated_bit_mask_evaluates_in_yara(tmp_path, input_byte, expected):
    expression = generate_bit_mask("(uint8(0) & 1)", 0b10110)

    rule = f"""
rule Bit_Mask
{{
    condition:
        {expression} == {expected}
}}
"""

    rule_path = tmp_path / "bit-mask.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(bytes([input_byte]))

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Bit_Mask" in result.stdout

@pytest.mark.parametrize("top", range(32))
def test_generated_polymod_tap(tmp_path, top):
    generators = (
        0x3B6A57B2,
        0x26508E6D,
        0x1EA119FA,
        0x3D4233DD,
        0x2A1462B3,
    )

    expected = 0

    for bit, generator in enumerate(generators):
        if (top >> bit) & 1:
            expected ^= generator

    checksum = top << 25
    expression = generate_polymod_tap(str(checksum))

    rule = f"""
rule Polymod_Tap
{{
    condition:
        {expression} == {expected}
}}
"""

    rule_path = tmp_path / "polymod-tap.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"X")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Tap" in result.stdout

@pytest.mark.parametrize(
    ("checksum", "value"),
    [
        (1, 0),
        (1, 31),
        (0b10101 << 25, 7),
        (0x12345678, 17),
        (0x3fffffff, 31),
    ],
)
def test_generated_polymod_step(tmp_path, checksum, value):
    expected = reference_polymod_step(checksum, value)
    expression = generate_polymod_step(str(checksum), str(value))

    rule = f"""
rule Polymod_Step
{{
    condition:
        {expression} == {expected}
}}
"""

    rule_path = tmp_path / "polymod-step.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"X")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Step" in result.stdout

@pytest.mark.parametrize(
    "values",
    [
        [0],
        [31],
        [0, 1, 2, 3],
        [3, 3, 3, 0, 1, 2, 3],
        [31] * 20,
        [31] * 173,
    ],
)
def test_symbolic_polymod_matches_reference(values):
    state = generate_symbolic_polymod(len(values))

    result = 0

    for output_bit, terms in enumerate(state):
        bit = 0

        for term in terms:
            if term == ("constant",):
                bit ^= 1
            else:
                _, position, input_bit = term
                bit ^= (values[position] >> input_bit) & 1

        result |= bit << output_bit

    assert result == reference_polymod(values)

def test_generate_symbolic_bit_expression():
    terms = frozenset({
        ("input", 0, 2),
        ("input", 1, 4),
    })

    expression = generate_symbolic_bit_expression(
        terms,
        ["first", "second"],
    )

    assert expression == (
        "(((first >> 2) & 1) ^ ((second >> 4) & 1))"
    )


def test_generate_symbolic_bit_expression_with_constant():
    terms = frozenset({
        ("constant",),
        ("input", 0, 3),
    })

    expression = generate_symbolic_bit_expression(
        terms,
        ["value"],
    )

    assert expression == "(1 ^ ((value >> 3) & 1))"


def test_generate_symbolic_bit_expression_zero():
    expression = generate_symbolic_bit_expression(
        frozenset(),
        [],
    )

    assert expression == "0"

@pytest.mark.parametrize(
    ("values", "constant"),
    [
        ([0], 32),
        ([31], reference_polymod([31])),
        ([0, 1, 2, 3], reference_polymod([0, 1, 2, 3])),
        ([3, 3, 3, 0, 1, 2, 3], reference_polymod([3, 3, 3, 0, 1, 2, 3])),
    ],
)
def test_generated_polymod_check_evaluates_in_yara(
    tmp_path,
    values,
    constant,
):
    input_expressions = [str(value) for value in values]
    expression = generate_polymod_check(
        input_expressions,
        constant,
    )

    rule = f"""
rule Polymod_Check
{{
    condition:
        {expression}
}}
"""

    rule_path = tmp_path / "polymod-check.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"X")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Check" in result.stdout

@pytest.mark.parametrize(
    "values",
    [
        [0],
        [31],
        [0, 1, 2, 3],
        [3, 3, 3, 0, 1, 2, 3],
    ],
)
def test_generated_polymod_check_rejects_wrong_constant(
    tmp_path,
    values,
):
    input_expressions = [str(value) for value in values]
    wrong_constant = reference_polymod(values) ^ 1

    expression = generate_polymod_check(
        input_expressions,
        wrong_constant,
    )

    rule = f"""
rule Polymod_Check
{{
    condition:
        {expression}
}}
"""

    rule_path = tmp_path / "polymod-check.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"X")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Check" not in result.stdout
