rule Valid_Luhn_16
{
    strings:
        $candidate = /[0-9]{16}/

    condition:
        for any i in (1..#candidate) : (
            (
                (2 * (uint8(@candidate[i] + 0) - 48) - 9 * ((uint8(@candidate[i] + 0) - 48) \ 5)) +
                (uint8(@candidate[i] + 1) - 48) +
                (2 * (uint8(@candidate[i] + 2) - 48) - 9 * ((uint8(@candidate[i] + 2) - 48) \ 5)) +
                (uint8(@candidate[i] + 3) - 48) +
                (2 * (uint8(@candidate[i] + 4) - 48) - 9 * ((uint8(@candidate[i] + 4) - 48) \ 5)) +
                (uint8(@candidate[i] + 5) - 48) +
                (2 * (uint8(@candidate[i] + 6) - 48) - 9 * ((uint8(@candidate[i] + 6) - 48) \ 5)) +
                (uint8(@candidate[i] + 7) - 48) +
                (2 * (uint8(@candidate[i] + 8) - 48) - 9 * ((uint8(@candidate[i] + 8) - 48) \ 5)) +
                (uint8(@candidate[i] + 9) - 48) +
                (2 * (uint8(@candidate[i] + 10) - 48) - 9 * ((uint8(@candidate[i] + 10) - 48) \ 5)) +
                (uint8(@candidate[i] + 11) - 48) +
                (2 * (uint8(@candidate[i] + 12) - 48) - 9 * ((uint8(@candidate[i] + 12) - 48) \ 5)) +
                (uint8(@candidate[i] + 13) - 48) +
                (2 * (uint8(@candidate[i] + 14) - 48) - 9 * ((uint8(@candidate[i] + 14) - 48) \ 5)) +
                (uint8(@candidate[i] + 15) - 48)
            ) % 10 == 0
        )
}
