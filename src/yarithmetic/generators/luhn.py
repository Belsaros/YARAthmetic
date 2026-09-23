def generate_luhn16_rule() -> str:
    terms = []

    for offset in range(16):
        digit = f"(uint8(@candidate[i] + {offset}) - 48)"

        if offset % 2 == 0:
            term = f"(2 * {digit} - 9 * ({digit} \\ 5))"
        else:
            term = digit

        terms.append(term)

    checksum = " +\n                ".join(terms)

    return f"""\
rule Valid_Luhn_16
{{
    strings:
        $candidate = /[0-9]{{16}}/

    condition:
        for any i in (1..#candidate) : (
            (
                {checksum}
            ) % 10 == 0
        )
}}
"""
