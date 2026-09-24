CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

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

def generate_bech32_rule() -> str:
    return r"""
rule Bech32_Candidate
{
    strings:
        $candidate = /[!-~]+1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,}/ nocase

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
        )
}
"""
