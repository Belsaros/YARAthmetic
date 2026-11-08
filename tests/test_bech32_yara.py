import subprocess

import pytest

from yarithmetic.generators.bech32 import (
    apply_polymod_distance,
    apply_polymod_transition_matrix,
    generate_bech32_rule,
    generate_bit_mask,
    generate_charset_bit,
    generate_charset_value,
    generate_hrp_high_value,
    generate_hrp_low_value,
    generate_integer_threshold_expression,
    generate_packed_polymod_coefficient_expression,
    generate_polymod_check,
    generate_polymod_check_column_major,
    generate_polymod_check_from_bits,
    generate_polymod_distance_expression,
    generate_polymod_expression_from_bits,
    generate_polymod_inputs,
    generate_polymod_input_bits,
    generate_polymod_input_influence_masks,
    generate_polymod_input_influence_table,
    generate_polymod_tap,
    generate_polymod_transition_expression,
    generate_polymod_transition_matrix,
    generate_polymod_step,
    generate_separator_position_expression,
    generate_symbolic_bit_expression,
    generate_symbolic_polymod,
    pack_bits_into_63_bit_chunks,
    pack_polymod_coefficient_by_distance,
    pack_polymod_influence_table,
    select_packed_polymod_coefficient,
    select_packed_polymod_influence,
    transpose_symbolic_polymod,
)

from yarithmetic.reference.bech32 import (
        BECH32_CONSTANT,
        BECH32M_CONSTANT,
        polymod_step as reference_polymod_step,
        polymod as reference_polymod,
)

pytestmark = pytest.mark.bech32

def run_rule(
    tmp_path,
    value,
    *,
    shapes,
):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        generate_bech32_rule(
            shapes=shapes,
        ),
        encoding="utf-8",
    )

    sample_path.write_text(
        value,
        encoding="ascii",
    )

    return subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

def test_generated_bech32_rule_matches_candidate(tmp_path):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        generate_bech32_rule(
            shapes=[(45, 6)],
        ),
        encoding="utf-8",
    )

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

    rule_path.write_text(
        generate_bech32_rule(
            shapes=[(8, 1)],
        ),
        encoding="utf-8",
    )

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

def test_generated_bech32_rule_allows_90_character_candidate(tmp_path):
    value = (
        "an83characterlonghumanreadablepartthatcontainsthenumber1"
        "andtheexcludedcharactersbio1tt5tgs"
    )
    assert len(value) == 90

    result = run_rule(
        tmp_path,
        value,
        shapes=[(90, 83)],
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_rejects_data_part_shorter_than_checksum(tmp_path):
    value = "a1" + "q" * 5

    result = run_rule(
        tmp_path,
        value,
        shapes=[(8, 1)],
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_bech32_rule_allows_six_character_data_part(tmp_path):
    value = "A12UEL5L"
    assert len(value[value.rfind("1") + 1:]) == 6

    result = run_rule(
        tmp_path,
        value,
        shapes=[(8, 1)],
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_allows_lowercase_candidate(tmp_path):
    result = run_rule(
        tmp_path,
        "a12uel5l",
        shapes=[(8, 1)],
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_allows_uppercase_candidate(tmp_path):
    result = run_rule(
        tmp_path,
        "A12UEL5L",
        shapes=[(8, 1)],
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_rejects_mixed_case_candidate(tmp_path):
    result = run_rule(
        tmp_path,
        "a1QQQQQQ",
        shapes=[(8, 1)],
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_generated_bech32_rule_rejects_mixed_case_hrp(tmp_path):
    result = run_rule(
        tmp_path,
        "aB1qqqqqq",
        shapes=[(9, 2)],
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_bech32_rule_allows_one_in_hrp(tmp_path):
    value = "foo1bar1yfwynv"

    assert len(value) == 14
    assert value.rfind("1") == 7

    result = run_rule(
        tmp_path,
        value,
        shapes=[(14, 7)],
    )

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

@pytest.mark.parametrize(
    ("char", "expected"),
    [
        ("A", ord("a") & 31),
        ("a", ord("a") & 31),
        ("Z", ord("z") & 31),
        ("z", ord("z") & 31),
        ("?", ord("?") & 31),
        ("1", ord("1") & 31),
    ],
)
def test_generated_hrp_low_value_evaluates_in_yara(
    tmp_path,
    char,
    expected,
):
    expression = generate_hrp_low_value("uint8(0)")

    rule = f"""
rule HRP_Low_Value
{{
    condition:
        {expression} == {expected}
}}
"""

    rule_path = tmp_path / "hrp-low.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(char.encode("ascii"))

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "HRP_Low_Value" in result.stdout

@pytest.mark.parametrize("byte", range(33, 127))
def test_generated_hrp_high_value_evaluates_in_yara(
    tmp_path,
    byte,
):
    char = chr(byte)
    expected = ord(char.lower()) >> 5

    expression = generate_hrp_high_value("uint8(0)")

    rule = f"""
rule HRP_High_Value
{{
    condition:
        {expression} == {expected}
}}
"""

    rule_path = tmp_path / "hrp-high.yar"
    sample_path = tmp_path / "sample.bin"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(bytes([byte]))

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "HRP_High_Value" in result.stdout

def test_generate_polymod_inputs_for_known_shape():
    inputs = generate_polymod_inputs(
        "base",
        hrp_length=2,
        candidate_length=10,
    )

    byte0 = "uint8((base) + 0)"
    byte1 = "uint8((base) + 1)"

    assert inputs == [
        generate_hrp_high_value(byte0),
        generate_hrp_high_value(byte1),
        "0",
        generate_hrp_low_value(byte0),
        generate_hrp_low_value(byte1),
        generate_charset_value("uint8((base) + 3)"),
        generate_charset_value("uint8((base) + 4)"),
        generate_charset_value("uint8((base) + 5)"),
        generate_charset_value("uint8((base) + 6)"),
        generate_charset_value("uint8((base) + 7)"),
        generate_charset_value("uint8((base) + 8)"),
        generate_charset_value("uint8((base) + 9)"),
    ]

def test_generated_polymod_check_validates_real_bech32_bytes(tmp_path):
    value = "A12UEL5L"

    inputs = generate_polymod_inputs(
        "0",
        hrp_length=1,
        candidate_length=len(value),
    )

    condition = generate_polymod_check(
        inputs,
        BECH32_CONSTANT,
    )

    rule = f"""
rule Bech32_Checksum
{{
    condition:
        filesize == {len(value)} and
        {condition}
}}
"""

    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_text(value, encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Checksum" in result.stdout

def test_generated_polymod_check_rejects_corrupt_bech32_bytes(tmp_path):
    value = "A12UEL5M"

    inputs = generate_polymod_inputs(
        "0",
        hrp_length=1,
        candidate_length=len(value),
    )

    condition = generate_polymod_check(
        inputs,
        BECH32_CONSTANT,
    )

    rule = f"""
rule Bech32_Checksum
{{
    condition:
        filesize == {len(value)} and
        {condition}
}}
"""

    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_text(value, encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_polymod_check_validates_real_bech32m_bytes(tmp_path):
    value = "A1LQFN3A"

    inputs = generate_polymod_inputs(
        "0",
        hrp_length=1,
        candidate_length=len(value),
    )

    condition = generate_polymod_check(
        inputs,
        BECH32M_CONSTANT,
    )

    rule = f"""
rule Bech32m_Checksum
{{
    condition:
        filesize == {len(value)} and
        {condition}
}}
"""

    rule_path = tmp_path / "bech32m.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_text(value, encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32m_Checksum" in result.stdout

def test_transpose_symbolic_polymod():
    state = generate_symbolic_polymod(1)

    constant_mask, input_masks = transpose_symbolic_polymod(state)

    assert constant_mask == 32

    for input_bit in range(5):
        values = [1 << input_bit]

        expected_delta = (
            reference_polymod(values)
            ^ reference_polymod([0])
        )

        assert input_masks[("input", 0, input_bit)] == expected_delta

def test_transpose_symbolic_polymod_maximum_length():
    values = [
        (position * 17 + 3) & 31
        for position in range(173)
    ]

    state = generate_symbolic_polymod(len(values))
    constant_mask, input_masks = transpose_symbolic_polymod(state)

    result = constant_mask

    for position, value in enumerate(values):
        for bit in range(5):
            if (value >> bit) & 1:
                result ^= input_masks.get(
                    ("input", position, bit),
                    0,
                )

    assert result == reference_polymod(values)

@pytest.mark.parametrize(
    "values",
    [
        [0],
        [31],
        [0, 1, 2, 3],
        [3, 3, 3, 0, 1, 2, 3],
    ],
)
def test_generated_column_major_polymod_check_evaluates_in_yara(
    tmp_path,
    values,
):
    input_expressions = [str(value) for value in values]
    expected = reference_polymod(values)

    condition = generate_polymod_check_column_major(
        input_expressions,
        expected,
    )

    rule = f"""
rule Polymod_Column_Major
{{
    condition:
        {condition}
}}
"""

    rule_path = tmp_path / "polymod-column-major.yar"
    sample_path = tmp_path / "sample"
    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Column_Major" in result.stdout

@pytest.mark.parametrize(
    "values",
    [
        [0],
        [31],
        [0, 1, 2, 3],
        [3, 3, 3, 0, 1, 2, 3],
    ],
)
def test_generated_column_major_polymod_check_rejects_wrong_constant(
    tmp_path,
    values,
):
    input_expressions = [str(value) for value in values]
    wrong_constant = reference_polymod(values) ^ 1

    condition = generate_polymod_check_column_major(
        input_expressions,
        wrong_constant,
    )

    rule = f"""
rule Polymod_Column_Major
{{
    condition:
        {condition}
}}
"""

    rule_path = tmp_path / "polymod-column-major.yar"
    sample_path = tmp_path / "sample"
    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

@pytest.mark.parametrize("bit", range(5))
def test_generated_charset_bit_evaluates_in_yara(
    tmp_path,
    bit,
):
    for char in CHARSET:
        expected = (CHARSET.index(char) >> bit) & 1

        for representation in {char.lower(), char.upper()}:
            expression = generate_charset_bit(
                str(ord(representation)),
                bit,
            )

            rule = f"""
rule Charset_Bit
{{
    condition:
        {expression} == {expected}
}}
"""

            rule_path = tmp_path / "charset-bit.yar"
            sample_path = tmp_path / "sample"

            rule_path.write_text(rule, encoding="utf-8")
            sample_path.write_bytes(b"")

            result = subprocess.run(
                ["yara", str(rule_path), str(sample_path)],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, (
                representation,
                bit,
                result.stderr,
            )
            assert "Charset_Bit" in result.stdout, (
                representation,
                bit,
                expression,
            )

def test_generate_polymod_expression_from_bits():
    expression = generate_polymod_expression_from_bits(
        [
            ["0", "0", "0", "0", "0"],
        ],
    )

    assert isinstance(expression, str)
    assert expression

@pytest.mark.parametrize(
    "values",
    [
        [0],
        [31],
        [0, 1, 2, 3],
        [3, 3, 3, 0, 1, 2, 3],
    ],
)

def test_generated_polymod_check_from_bits_evaluates_in_yara(
    tmp_path,
    values,
):
    input_bits = [
        [
            str((value >> bit) & 1)
            for bit in range(5)
        ]
        for value in values
    ]

    expected = reference_polymod(values)

    condition = generate_polymod_check_from_bits(
        input_bits,
        expected,
    )

    rule = f"""
rule Polymod_From_Bits
{{
    condition:
        {condition}
}}
"""

    rule_path = tmp_path / "polymod-from-bits.yar"
    sample_path = tmp_path / "sample"
    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(b"")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_From_Bits" in result.stdout

@pytest.mark.parametrize(
    "bits",
    [
        [],
        ["0"],
        ["0", "0", "0", "0"],
        ["0", "0", "0", "0", "0", "0"],
    ],
)
def test_generate_polymod_check_from_bits_rejects_invalid_width(bits):
    with pytest.raises(
        ValueError,
        match="exactly 5 bits",
    ):
        generate_polymod_check_from_bits(
            [bits],
            1,
        )

def test_generate_polymod_input_bits_shape():
    input_bits = generate_polymod_input_bits(
        "@candidate[i]",
        2,
        10,
    )

    # N = L + H
    assert len(input_bits) == 12

    # Every polymod symbol is five bits.
    assert all(len(bits) == 5 for bits in input_bits)

    # HRP expansion separator is zero.
    assert input_bits[2] == ["0"] * 5

def test_generate_polymod_input_bits_matches_integer_inputs_in_yara(
    tmp_path,
):
    candidate = b"A12UEL5L"
    hrp_length = 1
    candidate_length = len(candidate)

    old_inputs = generate_polymod_inputs(
        "@candidate[1]",
        hrp_length,
        candidate_length,
    )
    new_bits = generate_polymod_input_bits(
        "@candidate[1]",
        hrp_length,
        candidate_length,
    )

    assert len(old_inputs) == len(new_bits)

    comparisons = []

    for old_expression, bits in zip(old_inputs, new_bits):
        reconstructed = " | ".join(
            f"(({bit_expression}) << {bit})"
            for bit, bit_expression in enumerate(bits)
        )

        comparisons.append(
            f"(({old_expression}) == ({reconstructed}))"
        )

    condition = " and\n        ".join(comparisons)

    rule = f"""
rule Polymod_Input_Bits_Equivalent
{{
    strings:
        $candidate = "A12UEL5L" ascii

    condition:
        for any i in (1..#candidate) : (
            {condition}
        )
}}
"""

    rule_path = tmp_path / "polymod-input-bits-equivalent.yar"
    sample_path = tmp_path / "sample"

    rule_path.write_text(rule, encoding="utf-8")
    sample_path.write_bytes(candidate)

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Input_Bits_Equivalent" in result.stdout

def test_generated_rule_accepts_bech32m(tmp_path):
    result = run_rule(
        tmp_path,
        "A1LQFN3A",
        shapes=[(8, 1)],
    )

    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_validates_checksum(
    tmp_path,
):
    shapes = [
        (8, 1),
        (45, 6),
    ]

    valid = run_rule(
        tmp_path,
        "A12UEL5L",
        shapes=shapes,
    )

    invalid = run_rule(
        tmp_path,
        "A12UEL5M",
        shapes=shapes,
    )

    different_shape = run_rule(
        tmp_path,
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        shapes=shapes,
    )

    assert "Bech32_Candidate" in valid.stdout
    assert invalid.stdout == ""
    assert "Bech32_Candidate" in different_shape.stdout

def test_yara_singleton_for_can_bind_integer_expression(tmp_path):
    rule_path = tmp_path / "singleton.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        """
rule Singleton_For
{
    condition:
        for any value in (40 + 2) : (
            value == 42
        )
}
""",
        encoding="utf-8",
    )

    sample_path.write_text(
        "anything",
        encoding="ascii",
    )

    result = subprocess.run(
        [
            "yara",
            str(rule_path),
            str(sample_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Singleton_For" in result.stdout

def test_generated_separator_position_expression():
    assert generate_separator_position_expression(
        "@candidate[i]",
        7,
    ) == "uint8(@candidate[i] + 7) == 49"

def test_yara_loop_variable_can_index_candidate(tmp_path):
    rule_path = tmp_path / "loop-offset.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        r"""
rule Loop_Offset
{
    strings:
        $candidate = /abc1def/

    condition:
        for any i in (1..#candidate) : (
            for any h in (1..6) : (
                uint8(@candidate[i] + h) == 49
            )
        )
}
""",
        encoding="utf-8",
    )

    sample_path.write_text(
        "abc1def",
        encoding="ascii",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Loop_Offset" in result.stdout

def test_yara_loop_range_can_depend_on_runtime_length(tmp_path):
    rule_path = tmp_path / "runtime-range.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        r"""
rule Runtime_Range
{
    strings:
        $candidate = /a1bcdefg/

    condition:
        for any i in (1..#candidate) : (
            for any length in (!candidate[i]) : (
                for any h in (1..length - 7) : (
                    uint8(@candidate[i] + h) == 49
                )
            )
        )
}
""",
        encoding="utf-8",
    )

    sample_path.write_text(
        "a1bcdefg",
        encoding="ascii",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Runtime_Range" in result.stdout

@pytest.mark.parametrize("distance", [0, 1, 2, 31, 62, 63, 64, 89, 90, 172])
def test_polymod_input_influence_depends_only_on_distance(distance):
    short_length = distance + 1
    long_length = distance + 2

    short_state = generate_symbolic_polymod(short_length)
    _, short_masks = transpose_symbolic_polymod(short_state)

    long_state = generate_symbolic_polymod(long_length)
    _, long_masks = transpose_symbolic_polymod(long_state)

    for bit in range(5):
        assert short_masks[("input", 0, bit)] == long_masks[
            ("input", 1, bit)
        ]

@pytest.mark.parametrize("distance", [0, 1, 2, 31, 62, 63, 64, 89, 90, 172])
def test_polymod_input_influence_masks(distance):
    state = generate_symbolic_polymod(distance + 1)
    _, input_masks = transpose_symbolic_polymod(state)

    expected = tuple(
        input_masks[("input", 0, bit)]
        for bit in range(5)
    )

    assert generate_polymod_input_influence_masks(distance) == expected

def test_polymod_input_influence_table_matches_reference():
    table = generate_polymod_input_influence_table(172)

    assert len(table) == 173

    for distance, masks in enumerate(table):
        assert masks == generate_polymod_input_influence_masks(distance)

def test_pack_bits_into_63_bit_chunks():
    bits = [
        1 if index in {0, 1, 62, 63, 64, 125, 126, 172} else 0
        for index in range(173)
    ]

    chunks = pack_bits_into_63_bit_chunks(bits)

    assert len(chunks) == 3

    for index, expected in enumerate(bits):
        chunk = chunks[index // 63]
        bit = (chunk >> (index % 63)) & 1
        assert bit == expected

@pytest.mark.parametrize(
    ("input_bit", "output_bit"),
    [
        (0, 0),
        (0, 29),
        (2, 15),
        (4, 0),
        (4, 29),
    ],
)
def test_pack_polymod_coefficient_by_distance(input_bit, output_bit):
    table = generate_polymod_input_influence_table(172)

    chunks = pack_polymod_coefficient_by_distance(
        table,
        input_bit,
        output_bit,
    )

    assert len(chunks) == 3

    for distance, masks in enumerate(table):
        expected = (masks[input_bit] >> output_bit) & 1
        actual = (
            chunks[distance // 63]
            >> (distance % 63)
        ) & 1

        assert actual == expected

def test_select_packed_polymod_coefficient():
    table = generate_polymod_input_influence_table(172)
    chunks = pack_polymod_coefficient_by_distance(
        table,
        2,
        15,
    )

    for distance, masks in enumerate(table):
        expected = (masks[2] >> 15) & 1
        actual = select_packed_polymod_coefficient(
            chunks,
            distance,
        )

        assert actual == expected

@pytest.mark.parametrize("threshold", [63, 126])
def test_generate_integer_threshold_expression(tmp_path, threshold):
    rule_path = tmp_path / "threshold.yar"

    expression = generate_integer_threshold_expression(
        "d",
        threshold,
    )

    conditions = []

    for distance in range(173):
        expected = int(distance >= threshold)
        conditions.append(
            f"({expression.replace('d', str(distance))}) == {expected}"
        )

    rule_path.write_text(
        """
rule Integer_Threshold
{
    condition:
        %s
}
"""
        % "\n        and ".join(conditions),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(rule_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Integer_Threshold" in result.stdout

def test_generated_packed_polymod_coefficient_expression(tmp_path):
    table = generate_polymod_input_influence_table(172)
    chunks = pack_polymod_coefficient_by_distance(
        table,
        2,
        15,
    )

    expression = generate_packed_polymod_coefficient_expression(
        chunks,
        "__DISTANCE__",
    )

    conditions = []

    for distance in range(173):
        expected = select_packed_polymod_coefficient(
            chunks,
            distance,
        )
        conditions.append(
            f"({expression.replace('__DISTANCE__', str(distance))}) == {expected}"
        )

    rule_path = tmp_path / "packed-coefficient.yar"

    rule_path.write_text(
        """
rule Packed_Coefficient
{
    condition:
        %s
}
"""
        % "\n        and ".join(conditions),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(rule_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Packed_Coefficient" in result.stdout

def test_yara_zero_minus_integer_bit_produces_mask(tmp_path):
    rule_path = tmp_path / "integer-mask.yar"

    rule_path.write_text(
        r"""
rule Integer_Mask
{
    condition:
        (0x12345678 & (0 - ((62 + 193) >> 8))) == 0
        and
        (0x12345678 & (0 - ((63 + 193) >> 8))) == 0x12345678
}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(rule_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Integer_Mask" in result.stdout

def test_pack_polymod_influence_table():
    table = generate_polymod_input_influence_table(172)

    packed = pack_polymod_influence_table(table)

    assert len(packed) == 5

    for input_bit in range(5):
        assert len(packed[input_bit]) == 30

        for output_bit in range(30):
            chunks = packed[input_bit][output_bit]

            assert len(chunks) == 3

            for distance, masks in enumerate(table):
                expected = (
                    masks[input_bit] >> output_bit
                ) & 1

                actual = (
                    chunks[distance // 63]
                    >> (distance % 63)
                ) & 1

                assert actual == expected

@pytest.mark.parametrize(
    ("distance", "value"),
    [
        (0, 0),
        (0, 31),
        (1, 1),
        (31, 17),
        (62, 9),
        (63, 21),
        (64, 6),
        (125, 27),
        (126, 13),
        (172, 31),
    ],
)
def test_select_packed_polymod_influence(distance, value):
    table = generate_polymod_input_influence_table(172)
    packed = pack_polymod_influence_table(table)

    expected = 0

    for input_bit in range(5):
        if (value >> input_bit) & 1:
            expected ^= table[distance][input_bit]

    assert select_packed_polymod_influence(
        packed,
        distance,
        value,
    ) == expected

def test_yara_nested_singleton_for_can_chain_integer_bindings(
    tmp_path,
):
    rule_path = tmp_path / "nested-bindings.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        """
rule Nested_Bindings
{
    condition:
        for any s0 in (1) : (
            for any s1 in (s0 << 5) : (
                for any s2 in (s1 << 5) : (
                    for any s3 in (s2 << 5) : (
                        s3 == 32768
                    )
                )
            )
        )
}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Nested_Bindings" in result.stdout

def test_yara_chained_binding_can_apply_polymod_transition(
    tmp_path,
):
    rule_path = tmp_path / "polymod-transition.yar"
    sample_path = tmp_path / "sample.txt"

    initial = 0x3B6A57B2

    expected = reference_polymod_step(
        initial,
        0,
    )

    rule_path.write_text(
        f"""
rule Polymod_Transition
{{
    condition:
        for any s0 in ({initial}) : (
            for any top in (s0 >> 25) : (
                for any s1 in (
                    ((s0 & 0x1ffffff) << 5)
                    ^ (0x3b6a57b2 & (0 - (top & 1)))
                    ^ (0x26508e6d & (0 - ((top >> 1) & 1)))
                    ^ (0x1ea119fa & (0 - ((top >> 2) & 1)))
                    ^ (0x3d4233dd & (0 - ((top >> 3) & 1)))
                    ^ (0x2a1462b3 & (0 - ((top >> 4) & 1)))
                ) : (
                    s1 == {expected}
                )
            )
        )
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Transition" in result.stdout

@pytest.mark.parametrize(
    ("enabled", "expected"),
    [
        (0, 0x12345678),
        (
            1,
            reference_polymod_step(
                0x12345678,
                0,
            ),
        ),
    ],
)
def test_yara_can_conditionally_apply_polymod_transition(
    tmp_path,
    enabled,
    expected,
):
    rule_path = tmp_path / "conditional-transition.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        f"""
rule Conditional_Transition
{{
    condition:
        for any s0 in (0x12345678) : (
            for any top in (s0 >> 25) : (
                for any advanced in (
                    ((s0 & 0x1ffffff) << 5)
                    ^ (0x3b6a57b2 & (0 - (top & 1)))
                    ^ (0x26508e6d & (0 - ((top >> 1) & 1)))
                    ^ (0x1ea119fa & (0 - ((top >> 2) & 1)))
                    ^ (0x3d4233dd & (0 - ((top >> 3) & 1)))
                    ^ (0x2a1462b3 & (0 - ((top >> 4) & 1)))
                ) : (
                    for any selected in (
                        s0
                        ^ (
                            (s0 ^ advanced)
                            & (0 - {enabled})
                        )
                    ) : (
                        selected == {expected}
                    )
                )
            )
        )
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Conditional_Transition" in result.stdout

@pytest.mark.parametrize(
    "distance",
    [0, 1, 2, 3, 5, 31, 62, 63, 64, 125, 126, 127, 128, 172],
)
def test_polymod_distance_by_binary_powers(distance):
    expected = 1

    for _ in range(distance):
        expected = reference_polymod_step(expected, 0)

    actual = 1

    for bit in range(8):
        if (distance >> bit) & 1:
            for _ in range(1 << bit):
                actual = reference_polymod_step(actual, 0)

    assert actual == expected

@pytest.mark.parametrize(
    "steps",
    [1, 2, 4, 8, 16, 32, 64, 128],
)
def test_polymod_transition_matrix_matches_reference(steps):
    matrix = generate_polymod_transition_matrix(steps)

    assert len(matrix) == 30

    for input_bit in range(30):
        expected = 1 << input_bit

        for _ in range(steps):
            expected = reference_polymod_step(
                expected,
                0,
            )

        assert matrix[input_bit] == expected

@pytest.mark.parametrize(
    ("steps", "state"),
    [
        (1, 0),
        (1, 1),
        (1, 0x3fffffff),
        (2, 0x12345678),
        (4, 0x2abcdef0),
        (8, 0x15555555),
        (16, 0x3b6a57b2),
        (32, 0x26508e6d),
        (64, 0x1ea119fa),
        (128, 0x3d4233dd),
    ],
)
def test_apply_polymod_transition_matrix(steps, state):
    matrix = generate_polymod_transition_matrix(steps)

    expected = state

    for _ in range(steps):
        expected = reference_polymod_step(
            expected,
            0,
        )

    assert apply_polymod_transition_matrix(
        matrix,
        state,
    ) == expected

@pytest.mark.parametrize(
    ("distance", "state"),
    [
        (0, 0x12345678),
        (1, 0x12345678),
        (2, 0x12345678),
        (3, 0x12345678),
        (7, 0x2abcdef0),
        (31, 0x15555555),
        (62, 0x3b6a57b2),
        (63, 0x26508e6d),
        (64, 0x1ea119fa),
        (127, 0x3d4233dd),
        (128, 0x2a1462b3),
        (172, 0x12345678),
    ],
)
def test_apply_polymod_distance(distance, state):
    expected = state

    for _ in range(distance):
        expected = reference_polymod_step(
            expected,
            0,
        )

    assert apply_polymod_distance(
        state,
        distance,
    ) == expected

@pytest.mark.parametrize(
    ("steps", "state"),
    [
        (1, 0x12345678),
        (2, 0x2abcdef0),
        (8, 0x15555555),
        (32, 0x3b6a57b2),
        (128, 0x26508e6d),
    ],
)
def test_generated_polymod_transition_expression_in_yara(
    tmp_path,
    steps,
    state,
):
    matrix = generate_polymod_transition_matrix(steps)

    expression = generate_polymod_transition_expression(
        matrix,
        "state",
    )

    expected = apply_polymod_transition_matrix(
        matrix,
        state,
    )

    rule_path = tmp_path / "matrix-transition.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        f"""
rule Matrix_Transition
{{
    condition:
        for any state in ({state}) : (
            ({expression}) == {expected}
        )
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Matrix_Transition" in result.stdout

@pytest.mark.parametrize(
    ("distance", "state"),
    [
        (0, 0x12345678),
        (1, 0x12345678),
        (3, 0x12345678),
        (7, 0x2abcdef0),
        (31, 0x15555555),
        (63, 0x26508e6d),
        (64, 0x1ea119fa),
        (127, 0x3d4233dd),
        (128, 0x2a1462b3),
        (172, 0x12345678),
    ],
)
def test_generated_polymod_distance_expression_in_yara(
    tmp_path,
    distance,
    state,
):
    expected = apply_polymod_distance(
        state,
        distance,
    )

    expression = generate_polymod_distance_expression(
        "state",
        "distance",
        str(expected),
    )

    rule_path = tmp_path / "polymod-distance.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        f"""
rule Polymod_Distance
{{
    condition:
        for any state in ({state}) : (
            for any distance in ({distance}) : (
                {expression}
            )
        )
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Polymod_Distance" in result.stdout

@pytest.mark.parametrize(
    "depth",
    range(1, 12),
)
def test_yara_singleton_for_nesting_limit(
    tmp_path,
    depth,
):
    expression = "true"

    for level in reversed(range(depth)):
        expression = (
            f"for any value_{level} in ({level}) : ("
            f"{expression}"
            f")"
        )

    rule_path = tmp_path / "nesting.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        f"""
rule Nesting
{{
    condition:
        {expression}
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"depth={depth}: {result.stderr}"
    )
    assert "Nesting" in result.stdout

@pytest.mark.parametrize(
    "depth",
    range(1, 5),
)
def test_yara_supports_four_nested_singleton_for_loops(
    tmp_path,
    depth,
):
    expression = "true"

    for level in reversed(range(depth)):
        expression = (
            f"for any value_{level} in ({level}) : ("
            f"{expression}"
            f")"
        )

    rule_path = tmp_path / "nesting.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        f"""
rule Nesting
{{
    condition:
        {expression}
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Nesting" in result.stdout

def test_yara_rejects_five_nested_singleton_for_loops(
    tmp_path,
):
    expression = "true"

    for level in reversed(range(5)):
        expression = (
            f"for any value_{level} in ({level}) : ("
            f"{expression}"
            f")"
        )

    rule_path = tmp_path / "nesting.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        f"""
rule Nesting
{{
    condition:
        {expression}
}}
""",
        encoding="utf-8",
    )

    sample_path.write_text("x", encoding="ascii")

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "loop nesting limit exceeded" in result.stderr

def test_polymod_distance_matches_input_influence_table():
    table = generate_polymod_input_influence_table(172)

    for distance in range(173):
        for value in range(32):
            expected = 0

            for bit in range(5):
                if (value >> bit) & 1:
                    expected ^= table[distance][bit]

            assert apply_polymod_distance(
                value,
                distance,
            ) == expected
