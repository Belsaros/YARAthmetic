def generate_bech32_rule() -> str:
    return r"""
rule Bech32_Candidate
{
    strings:
        $candidate = /[!-~]+1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+/ nocase

    condition:
        for any i in (1..#candidate) : (
            !candidate[i] <= 90
            and
            (
                @candidate[i] == 0 or
                uint8(@candidate[i] - 1) < 33 or
                uint8(@candidate[i] - 1) > 126
            )
        )
}
"""
