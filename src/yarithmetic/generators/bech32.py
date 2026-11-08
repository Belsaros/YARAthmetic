CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

from yarithmetic.generators.compatibility import repeat_atom, require_match_lengths

from yarithmetic.reference.bech32 import (
        BECH32_CONSTANT,
        BECH32M_CONSTANT,
        polymod_step as reference_polymod_step,
)

CHARSET_VALUE_ANF = (
    # Output bit 0
    (
        (),
        (3,),
        (0, 3),
        (0, 4),
        (1, 4),
        (1, 6),
        (3, 4),
        (3, 6),
        (0, 1, 2),
        (0, 1, 3),
        (0, 2, 3),
        (1, 2, 6),
    ),

    # Output bit 1
    (
        (0,),
        (2,),
        (3,),
        (4,),
        (6,),
        (0, 1),
        (0, 3),
        (0, 4),
        (1, 3),
        (1, 6),
        (2, 3),
        (3, 4),
        (3, 6),
        (0, 1, 2),
        (0, 1, 3),
        (0, 2, 3),
        (0, 2, 6),
        (1, 2, 3),
        (1, 2, 4),
        (1, 2, 6),
    ),

    # Output bit 2
    (
        (3,),
        (4,),
        (6,),
        (1, 2),
        (1, 4),
        (1, 6),
        (3, 4),
        (3, 6),
        (0, 1, 2),
        (0, 1, 3),
        (0, 2, 6),
        (1, 2, 4),
        (1, 2, 6),
        (1, 3, 4),
    ),

    # Output bit 3
    (
        (0,),
        (4,),
        (6,),
        (0, 2),
        (0, 3),
        (0, 6),
        (1, 2),
        (2, 3),
        (2, 4),
        (3, 4),
        (3, 6),
        (0, 2, 6),
        (0, 3, 6),
        (1, 2, 3),
        (1, 2, 6),
    ),

    # Output bit 4
    (
        (),
        (0,),
        (1,),
        (4,),
        (0, 2),
        (0, 3),
        (0, 6),
        (1, 2),
        (1, 3),
        (1, 4),
        (2, 3),
        (2, 4),
        (2, 6),
        (0, 1, 3),
        (0, 1, 6),
        (0, 2, 3),
        (0, 3, 6),
        (1, 2, 3),
        (1, 2, 4),
        (1, 3, 4),
    ),
)

POLYMOD_GENERATORS = (
    0x3B6A57B2,
    0x26508E6D,
    0x1EA119FA,
    0x3D4233DD,
    0x2A1462B3,
)

def generate_polymod_distance_expression(
    state_expression,
    distance_expression,
    expected_expression,
):
    matrices = [
        generate_polymod_transition_matrix(1 << bit)
        for bit in range(8)
    ]

    state_names = [
        f"polymod_state_{bit}"
        for bit in range(8)
    ]

    expression = (
        f"{state_names[-1]} == {expected_expression}"
    )

    for bit in reversed(range(8)):
        previous_state = (
            state_expression
            if bit == 0
            else state_names[bit - 1]
        )

        advanced = generate_polymod_transition_expression(
            matrices[bit],
            previous_state,
        )

        distance_bit = (
            f"(({distance_expression} >> {bit}) & 1)"
        )

        selected = (
            f"({previous_state}"
            f" ^ (({previous_state} ^ ({advanced}))"
            f" & (0 - {distance_bit})))"
        )

        expression = (
            f"for any {state_names[bit]} in ({selected}) : ("
            f"{expression}"
            f")"
        )

    return expression

def generate_polymod_transition_expression(
    matrix,
    state_expression,
):
    terms = []

    for input_bit, transformed_basis in enumerate(matrix):
        state_bit = (
            f"(({state_expression} >> {input_bit}) & 1)"
        )

        terms.append(
            f"({hex(transformed_basis)}"
            f" & (0 - {state_bit}))"
        )

    return " ^ ".join(terms)

def apply_polymod_distance(state, distance):
    for bit in range(8):
        if (distance >> bit) & 1:
            matrix = generate_polymod_transition_matrix(
                1 << bit
            )
            state = apply_polymod_transition_matrix(
                matrix,
                state,
            )

    return state

def apply_polymod_transition_matrix(matrix, state):
    result = 0

    for input_bit in range(30):
        if (state >> input_bit) & 1:
            result ^= matrix[input_bit]

    return result

def generate_polymod_transition_matrix(steps):
    matrix = []

    for input_bit in range(30):
        state = 1 << input_bit

        for _ in range(steps):
            state = reference_polymod_step(state, 0)

        matrix.append(state)

    return tuple(matrix)

def select_packed_polymod_influence(
    packed,
    distance,
    value,
):
    influence = 0

    for input_bit in range(5):
        input_value = (value >> input_bit) & 1

        for output_bit in range(30):
            coefficient = select_packed_polymod_coefficient(
                packed[input_bit][output_bit],
                distance,
            )

            influence ^= (
                input_value
                & coefficient
            ) << output_bit

    return influence

def pack_polymod_influence_table(table):
    return tuple(
        tuple(
            pack_polymod_coefficient_by_distance(
                table,
                input_bit,
                output_bit,
            )
            for output_bit in range(30)
        )
        for input_bit in range(5)
    )

def generate_packed_polymod_coefficient_expression(
    chunks,
    distance_expression,
):
    m0, m1, m2 = chunks

    threshold_63 = generate_integer_threshold_expression(
        distance_expression,
        63,
    )
    threshold_126 = generate_integer_threshold_expression(
        distance_expression,
        126,
    )

    selected = (
        f"({hex(m0)}"
        f" ^ ({hex(m0 ^ m1)} & (0 - {threshold_63}))"
        f" ^ ({hex(m1 ^ m2)} & (0 - {threshold_126})))"
    )

    return (
        f"(({selected} >> "
        f"(({distance_expression}) % 63)) & 1)"
    )

def generate_integer_threshold_expression(
    value_expression,
    threshold,
):
    return (
        f"(({value_expression} + {256 - threshold}) >> 8)"
    )

def select_packed_polymod_coefficient(chunks, distance):
    m0, m1, m2 = chunks

    d01 = m0 ^ m1
    d12 = m1 ^ m2

    selected = (
        m0
        ^ (d01 & -int(distance >= 63))
        ^ (d12 & -int(distance >= 126))
    )

    return (selected >> (distance % 63)) & 1

def pack_polymod_coefficient_by_distance(
    table,
    input_bit,
    output_bit,
):
    bits = [
        (masks[input_bit] >> output_bit) & 1
        for masks in table
    ]

    return pack_bits_into_63_bit_chunks(bits)

def pack_bits_into_63_bit_chunks(bits):
    chunks = []

    for start in range(0, len(bits), 63):
        chunk = 0

        for offset, bit in enumerate(bits[start:start + 63]):
            chunk |= bit << offset

        chunks.append(chunk)

    return tuple(chunks)

def generate_polymod_input_influence_masks(distance):
    state = generate_symbolic_polymod(distance + 1)
    _, input_masks = transpose_symbolic_polymod(state)

    return tuple(
        input_masks[("input", 0, bit)]
        for bit in range(5)
    )

def generate_polymod_input_influence_table(max_distance):
    state = generate_symbolic_polymod(max_distance + 1)
    _, input_masks = transpose_symbolic_polymod(state)

    return [
        tuple(
            input_masks[("input", max_distance - distance, bit)]
            for bit in range(5)
        )
        for distance in range(max_distance + 1)
    ]

def generate_separator_position_expression(
    candidate_offset,
    position,
):
    return (
        f"uint8({candidate_offset} + {position}) == 49"
    )

def generate_shape_condition(
    candidate_length,
    hrp_length,
):
    input_bits = generate_polymod_input_bits(
        "@candidate[i]",
        hrp_length,
        candidate_length,
    )

    checksum = generate_polymod_expression_from_bits(
        input_bits
    )

    return f"""(
        !candidate[i] == {candidate_length}
        and uint8(@candidate[i] + {hrp_length}) == 49
        and for any polymod in ({checksum}) : (
            polymod == {hex(BECH32_CONSTANT)}
            or polymod == {hex(BECH32M_CONSTANT)}
        )
    )"""

def generate_polymod_input_bits(
    candidate_offset,
    hrp_length,
    candidate_length,
):
    input_bits = []

    # HRP high bits.
    for offset in range(hrp_length):
        byte_expression = (
            f"uint8(({candidate_offset}) + {offset})"
        )
        value_expression = generate_hrp_high_value(
            byte_expression
        )
        input_bits.append([
            f"(({value_expression} >> {bit}) & 1)"
            for bit in range(5)
        ])

    # HRP expansion separator.
    input_bits.append(["0"] * 5)

    # HRP low bits.
    for offset in range(hrp_length):
        byte_expression = (
            f"uint8(({candidate_offset}) + {offset})"
        )
        value_expression = generate_hrp_low_value(
            byte_expression
        )
        input_bits.append([
            f"(({value_expression} >> {bit}) & 1)"
            for bit in range(5)
        ])

    # Data + checksum characters.
    for offset in range(hrp_length + 1, candidate_length):
        byte_expression = (
            f"uint8(({candidate_offset}) + {offset})"
        )
        input_bits.append([
            generate_charset_bit(byte_expression, bit)
            for bit in range(5)
        ])

    return input_bits

def generate_polymod_expression_from_bits(
    input_bits,
) -> str:
    state = generate_symbolic_polymod(len(input_bits))
    constant_mask, input_masks = transpose_symbolic_polymod(state)

    terms = []

    for bits in input_bits:
        if len(bits) != 5:
            raise ValueError(
                "each polymod input must contain exactly 5 bits"
            )

    if constant_mask:
        terms.append(hex(constant_mask))

    for term, mask in sorted(input_masks.items()):
        _, position, bit = term
        bit_expression = input_bits[position][bit]

        terms.append(
            f"(({bit_expression}) * {hex(mask)})"
        )

    if not terms:
        return "0"

    return " ^ ".join(terms)


def generate_polymod_check_from_bits(
    input_bits,
    constant: int,
) -> str:
    expression = generate_polymod_expression_from_bits(
        input_bits
    )

    return f"(({expression}) == {hex(constant)})"

def _build_charset_bit_masks():
    masks = [0] * 5

    for value, char in enumerate(CHARSET):
        for representation in {char.lower(), char.upper()}:
            index = (
                (ord(representation) & 31)
                | ((ord(representation) >> 1) & 32)
            )

            for bit in range(5):
                if (value >> bit) & 1:
                    masks[bit] |= 1 << index

    return tuple(masks)


CHARSET_BIT_MASKS = _build_charset_bit_masks()

def generate_charset_bit(
    byte_expression: str,
    bit: int,
) -> str:
    if bit < 0 or bit > 4:
        raise ValueError("charset bit must be between 0 and 4")

    index = (
        f"((({byte_expression}) & 31) | "
        f"((({byte_expression}) >> 1) & 32))"
    )

    mask = CHARSET_BIT_MASKS[bit]

    return f"(({hex(mask)} >> {index}) & 1)"

def generate_polymod_check_column_major(
    input_expressions,
    constant: int,
) -> str:
    state = generate_symbolic_polymod(len(input_expressions))
    constant_mask, input_masks = transpose_symbolic_polymod(state)

    terms = []

    if constant_mask:
        terms.append(hex(constant_mask))

    for term, mask in sorted(input_masks.items()):
        _, position, bit = term
        input_expression = input_expressions[position]
        input_bit = f"(({input_expression} >> {bit}) & 1)"

        terms.append(
            f"({input_bit} * {hex(mask)})"
        )

    if not terms:
        expression = "0"
    else:
        expression = " ^ ".join(terms)

    return f"(({expression}) == {hex(constant)})"

def transpose_symbolic_polymod(state):
    constant_mask = 0
    input_masks = {}

    for output_bit, terms in enumerate(state):
        for term in terms:
            if term == ("constant",):
                constant_mask |= 1 << output_bit
            else:
                input_masks[term] = (
                    input_masks.get(term, 0)
                    | (1 << output_bit)
                )

    return constant_mask, input_masks

def generate_polymod_check(
    input_expressions,
    constant: int,
) -> str:
    state = generate_symbolic_polymod(len(input_expressions))

    checks = []

    for output_bit, terms in enumerate(state):
        expression = generate_symbolic_bit_expression(
            terms,
            input_expressions,
        )
        expected = (constant >> output_bit) & 1

        checks.append(f"({expression} == {expected})")

    return "(" + " and ".join(checks) + ")"

def generate_hrp_low_value(byte_expression: str) -> str:
    return f"(({byte_expression}) & 31)"

def generate_hrp_high_value(byte_expression: str) -> str:
    return (
        f"((({byte_expression}) >> 5) | "
        f"((((({byte_expression}) + 63) >> 7) ^ "
        f"((({byte_expression}) + 37) >> 7))))"
    )

def generate_polymod_inputs(
    candidate_offset: str,
    hrp_length: int,
    candidate_length: int,
):
    inputs = []

    for offset in range(hrp_length):
        byte_expression = f"uint8(({candidate_offset}) + {offset})"
        inputs.append(generate_hrp_high_value(byte_expression))

    inputs.append("0")

    for offset in range(hrp_length):
        byte_expression = f"uint8(({candidate_offset}) + {offset})"
        inputs.append(generate_hrp_low_value(byte_expression))

    for offset in range(hrp_length + 1, candidate_length):
        byte_expression = f"uint8(({candidate_offset}) + {offset})"
        inputs.append(generate_charset_value(byte_expression))

    return inputs

def generate_symbolic_bit_expression(terms, input_expressions):
    if not terms:
        return "0"

    expressions = []

    if ("constant",) in terms:
        expressions.append("1")

    input_terms = sorted(
        term for term in terms
        if term[0] == "input"
    )

    for _, position, bit in input_terms:
        expression = input_expressions[position]
        expressions.append(
            f"(({expression} >> {bit}) & 1)"
        )

    return "(" + " ^ ".join(expressions) + ")"

def generate_symbolic_polymod(symbol_count: int):
    state = [set() for _ in range(30)]
    state[0].add(("constant",))

    for position in range(symbol_count):
        top = state[25:30]
        new_state = [set() for _ in range(30)]

        # ((checksum & 0x1ffffff) << 5)
        for bit in range(25):
            new_state[bit + 5].symmetric_difference_update(state[bit])

        # ^ value
        for bit in range(5):
            new_state[bit].add(("input", position, bit))

        # ^ generator taps
        for top_bit, generator in enumerate(POLYMOD_GENERATORS):
            for output_bit in range(30):
                if (generator >> output_bit) & 1:
                    new_state[output_bit].symmetric_difference_update(
                        top[top_bit]
                    )

        state = new_state

    return tuple(frozenset(terms) for terms in state)

def generate_polymod_tap(checksum_expression: str) -> str:
    terms = []

    for bit, generator in enumerate(POLYMOD_GENERATORS):
        top_bit = f"(({checksum_expression} >> {25 + bit}) & 1)"
        terms.append(generate_bit_mask(top_bit, generator))

    return "(" + " ^ ".join(terms) + ")"

def generate_polymod_step(
    checksum_expression: str,
    value_expression: str,
) -> str:
    shifted = (
        f"((({checksum_expression}) & 0x1ffffff) << 5)"
    )
    tap = generate_polymod_tap(checksum_expression)

    return f"({shifted} ^ ({value_expression}) ^ {tap})"

def generate_bit_mask(bit_expression: str, mask: int) -> str:
    if mask == 0:
        return "0"

    terms = [
        f"({bit_expression})" if bit == 0
        else f"({bit_expression} << {bit})"
        for bit in range(mask.bit_length())
        if (mask >> bit) & 1
    ]

    return "(" + " | ".join(terms) + ")"

def generate_anf_term(byte_expression: str, term: tuple[int, ...]) -> str:
    if not term:
        return "1"

    factors = [
        f"(({byte_expression} >> {bit}) & 1)"
        for bit in term
    ]

    return "(" + " & ".join(factors) + ")"

def generate_anf_bit(byte_expression: str, terms, output_bit: int) -> str:
    expression = " ^ ".join(
        generate_anf_term(byte_expression, term)
        for term in terms
    )

    if output_bit:
        return f"(({expression}) << {output_bit})"

    return f"({expression})"

def generate_charset_value(byte_expression: str) -> str:
    bits = [
        generate_anf_bit(byte_expression, terms, output_bit)
        for output_bit, terms in enumerate(CHARSET_VALUE_ANF)
    ]

    return "(" + " | ".join(bits) + ")"

def generate_bech32_rule_unrolled(
    shapes=None,
    *,
    output_version=None,
) -> str:
    require_match_lengths(output_version)
    if shapes is None:
        shapes = [
            (candidate_length, hrp_length)
            for candidate_length in range(8, 91)
            for hrp_length in range(
                1,
                candidate_length - 6,
            )
        ]

    shape_conditions = [
        generate_shape_condition(
            candidate_length,
            hrp_length,
        )
        for candidate_length, hrp_length in shapes
    ]

    checksum_condition = "\n            or\n            ".join(
        shape_conditions
    )

    return f"""
rule Bech32_Candidate
{{
    strings:
        $candidate = /[!-~]+1{repeat_atom("[qpzry9x8gf2tvdw0s3jn54khce6mua7l]", 6, None, output_version)}/ nocase

    condition:
        for any i in (1..#candidate) : (
            !candidate[i] <= 90
            and
            (
                @candidate[i] == 0 or
                uint8(@candidate[i] - 1) < 33 or
                uint8(@candidate[i] - 1) > 126
            )
            and
            (
                for all j in (0..!candidate[i] - 1) : (
                    uint8(@candidate[i] + j) < 97 or
                    uint8(@candidate[i] + j) > 122
                )
                or
                for all j in (0..!candidate[i] - 1) : (
                    uint8(@candidate[i] + j) < 65 or
                    uint8(@candidate[i] + j) > 90
                )
            )
            and
            (
                {checksum_condition}
            )
        )
}}
"""


def generate_bech32_rule(shapes=None, *, output_version=None) -> str:
    """Generate full-coverage compact YARA, or unroll explicitly chosen shapes.

    A small shape list is cheaper to express directly. Full coverage shares
    polymod arithmetic across lengths and HRP positions instead of repeating
    that arithmetic for all 3,486 shapes. Requires YARA 3.5 or later;
    output_version enables release-specific regex workarounds.
    """
    if shapes is not None:
        return generate_bech32_rule_unrolled(shapes=shapes, output_version=output_version)
    from yarithmetic.generators.bech32_compact import generate_compact_bech32_rule

    return generate_compact_bech32_rule(output_version=output_version)
