def generate_luhn_rule(length: int) -> str:
    terms = []
    parity = length % 2

    for offset in range(length):
        digit = f"(uint8(@candidate[i] + {offset}) - 48)"

        if offset % 2 == parity:
            term = f"(2 * {digit} - 9 * ({digit} \\ 5))"
        else:
            term = digit

        terms.append(term)

    checksum = " +\n                ".join(terms)

    return f"""\
rule Valid_Luhn_{length}
{{
    strings:
        $candidate = /[0-9]{{{length}}}/

    condition:
        for any i in (1..#candidate) : (
            (
                {checksum}
            ) % 10 == 0
        )
}}
"""
