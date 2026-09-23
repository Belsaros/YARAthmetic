rule Valid_Luhn_19
{
    strings:
        $compact = /[0-9]{19}/

    condition:
        for any i in (1..#compact) : (
            (
                (uint8(@compact[i] + 0) - 48) +
                (2 * (uint8(@compact[i] + 1) - 48) - 9 * ((uint8(@compact[i] + 1) - 48) \ 5)) +
                (uint8(@compact[i] + 2) - 48) +
                (2 * (uint8(@compact[i] + 3) - 48) - 9 * ((uint8(@compact[i] + 3) - 48) \ 5)) +
                (uint8(@compact[i] + 4) - 48) +
                (2 * (uint8(@compact[i] + 5) - 48) - 9 * ((uint8(@compact[i] + 5) - 48) \ 5)) +
                (uint8(@compact[i] + 6) - 48) +
                (2 * (uint8(@compact[i] + 7) - 48) - 9 * ((uint8(@compact[i] + 7) - 48) \ 5)) +
                (uint8(@compact[i] + 8) - 48) +
                (2 * (uint8(@compact[i] + 9) - 48) - 9 * ((uint8(@compact[i] + 9) - 48) \ 5)) +
                (uint8(@compact[i] + 10) - 48) +
                (2 * (uint8(@compact[i] + 11) - 48) - 9 * ((uint8(@compact[i] + 11) - 48) \ 5)) +
                (uint8(@compact[i] + 12) - 48) +
                (2 * (uint8(@compact[i] + 13) - 48) - 9 * ((uint8(@compact[i] + 13) - 48) \ 5)) +
                (uint8(@compact[i] + 14) - 48) +
                (2 * (uint8(@compact[i] + 15) - 48) - 9 * ((uint8(@compact[i] + 15) - 48) \ 5)) +
                (uint8(@compact[i] + 16) - 48) +
                (2 * (uint8(@compact[i] + 17) - 48) - 9 * ((uint8(@compact[i] + 17) - 48) \ 5)) +
                (uint8(@compact[i] + 18) - 48)
            ) % 10 == 0
        )
}
