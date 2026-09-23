rule Valid_Luhn_16
{
    strings:
        $compact = /[0-9]{16}/
        $formatted = /[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4}/

    condition:
        for any i in (1..#compact) : (
            (
                    @compact[i] == 0 or
                    uint8(@compact[i] - 1) < 48 or
                    uint8(@compact[i] - 1) > 57
                )
                and
                (
                    @compact[i] + !compact[i] >= filesize or
                    uint8(@compact[i] + !compact[i]) < 48 or
                    uint8(@compact[i] + !compact[i]) > 57
                )
            and
            (
                (2 * (uint8(@compact[i] + 0) - 48) - 9 * ((uint8(@compact[i] + 0) - 48) \ 5)) +
                (uint8(@compact[i] + 1) - 48) +
                (2 * (uint8(@compact[i] + 2) - 48) - 9 * ((uint8(@compact[i] + 2) - 48) \ 5)) +
                (uint8(@compact[i] + 3) - 48) +
                (2 * (uint8(@compact[i] + 4) - 48) - 9 * ((uint8(@compact[i] + 4) - 48) \ 5)) +
                (uint8(@compact[i] + 5) - 48) +
                (2 * (uint8(@compact[i] + 6) - 48) - 9 * ((uint8(@compact[i] + 6) - 48) \ 5)) +
                (uint8(@compact[i] + 7) - 48) +
                (2 * (uint8(@compact[i] + 8) - 48) - 9 * ((uint8(@compact[i] + 8) - 48) \ 5)) +
                (uint8(@compact[i] + 9) - 48) +
                (2 * (uint8(@compact[i] + 10) - 48) - 9 * ((uint8(@compact[i] + 10) - 48) \ 5)) +
                (uint8(@compact[i] + 11) - 48) +
                (2 * (uint8(@compact[i] + 12) - 48) - 9 * ((uint8(@compact[i] + 12) - 48) \ 5)) +
                (uint8(@compact[i] + 13) - 48) +
                (2 * (uint8(@compact[i] + 14) - 48) - 9 * ((uint8(@compact[i] + 14) - 48) \ 5)) +
                (uint8(@compact[i] + 15) - 48)
            ) % 10 == 0
        )
        or
        for any i in (1..#formatted) : (
            (
                    @formatted[i] == 0 or
                    uint8(@formatted[i] - 1) < 48 or
                    uint8(@formatted[i] - 1) > 57
                )
                and
                (
                    @formatted[i] + !formatted[i] >= filesize or
                    uint8(@formatted[i] + !formatted[i]) < 48 or
                    uint8(@formatted[i] + !formatted[i]) > 57
                )
            and
            (
                (2 * (uint8(@formatted[i] + 0) - 48) - 9 * ((uint8(@formatted[i] + 0) - 48) \ 5)) +
                (uint8(@formatted[i] + 1) - 48) +
                (2 * (uint8(@formatted[i] + 2) - 48) - 9 * ((uint8(@formatted[i] + 2) - 48) \ 5)) +
                (uint8(@formatted[i] + 3) - 48) +
                (2 * (uint8(@formatted[i] + 5) - 48) - 9 * ((uint8(@formatted[i] + 5) - 48) \ 5)) +
                (uint8(@formatted[i] + 6) - 48) +
                (2 * (uint8(@formatted[i] + 7) - 48) - 9 * ((uint8(@formatted[i] + 7) - 48) \ 5)) +
                (uint8(@formatted[i] + 8) - 48) +
                (2 * (uint8(@formatted[i] + 10) - 48) - 9 * ((uint8(@formatted[i] + 10) - 48) \ 5)) +
                (uint8(@formatted[i] + 11) - 48) +
                (2 * (uint8(@formatted[i] + 12) - 48) - 9 * ((uint8(@formatted[i] + 12) - 48) \ 5)) +
                (uint8(@formatted[i] + 13) - 48) +
                (2 * (uint8(@formatted[i] + 15) - 48) - 9 * ((uint8(@formatted[i] + 15) - 48) \ 5)) +
                (uint8(@formatted[i] + 16) - 48) +
                (2 * (uint8(@formatted[i] + 17) - 48) - 9 * ((uint8(@formatted[i] + 17) - 48) \ 5)) +
                (uint8(@formatted[i] + 18) - 48)
            ) % 10 == 0
        )
}
