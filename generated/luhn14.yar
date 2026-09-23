rule Valid_Luhn_14
{
    strings:
        $compact = /[0-9]{14}/

    condition:
        for any i in (1..#compact) : (
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
                (uint8(@compact[i] + 13) - 48)
            ) % 10 == 0
        )
}
