from yarithmetic.generators.compatibility import parse_output_version, repeat_atom


def generate_checksum(candidate: str, digit_offsets: list[int]) -> str:
    parity = len(digit_offsets) % 2
    terms = []

    for index, offset in enumerate(digit_offsets):
        digit = f"(uint8(@{candidate}[i] + {offset}) - 48)"

        if index % 2 == parity:
            term = f"(2 * {digit} - 9 * ({digit} \\ 5))"
        else:
            term = digit

        terms.append(term)

    return " +\n                ".join(terms)

def generate_digit_boundaries(candidate: str, length=None) -> str:
    offset = f"@{candidate}[i]"
    candidate_length = str(length) if length is not None else f"!{candidate}[i]"
    end = f"@{candidate}[i] + {candidate_length}"

    return f"""\
(
                    {offset} == 0 or
                    uint8({offset} - 1) < 48 or
                    uint8({offset} - 1) > 57
                )
                and
                (
                    {end} >= filesize or
                    uint8({end}) < 48 or
                    uint8({end}) > 57
                )"""

def generate_formatted_regex(groups: list[int], output_version=None) -> str:
    parts = [repeat_atom("[0-9]", size, size, output_version) for size in groups]
    return "[ -]".join(parts)


def generate_digit_offsets(groups: list[int]) -> list[int]:
    offsets = []
    offset = 0

    for group_index, group_size in enumerate(groups):
        for _ in range(group_size):
            offsets.append(offset)
            offset += 1

        if group_index < len(groups) - 1:
            offset += 1

    return offsets

def generate_luhn_rule(length: int, *, output_version=None) -> str:
    """Generate Luhn validation, optionally targeting a classic YARA release."""
    version = parse_output_version(output_version)
    fixed_lengths = version is not None and version < (3, 5, 0)
    compact_boundaries = generate_digit_boundaries(
        "compact", length if fixed_lengths else None,
    )
    compact_checksum = generate_checksum(
        "compact",
        list(range(length)),
    )

    strings = [
        f"        $compact = /{repeat_atom('[0-9]', length, length, output_version)}/"
    ]

    conditions = [
        f"""\
        for any i in (1..#compact) : (
            {compact_boundaries}
            and
            (
                {compact_checksum}
            ) % 10 == 0
        )"""
    ]

    layouts = {
            14: [4, 6, 4],
            15: [4, 6, 5],
            16: [4, 4, 4, 4],
            19: [4, 4, 4, 4, 3],
        }

    if length in layouts:
        groups = layouts[length]

        formatted_regex = generate_formatted_regex(groups, output_version)
        formatted_offsets = generate_digit_offsets(groups)
        formatted_boundaries = generate_digit_boundaries(
            "formatted", length + len(groups) - 1 if fixed_lengths else None,
        )
        
        formatted_checksum = generate_checksum(
            "formatted",
            formatted_offsets,
        )

        strings.append(
            f"        $formatted = /{formatted_regex}/"
        )
        conditions.append(
            f"""\
        for any i in (1..#formatted) : (
            {formatted_boundaries}
            and
            (
                {formatted_checksum}
            ) % 10 == 0
        )"""
        )

    strings_source = "\n".join(strings)
    condition_source = "\n        or\n".join(conditions)

    return f"""\
rule Valid_Luhn_{length}
{{
    strings:
{strings_source}

    condition:
{condition_source}
}}
"""
