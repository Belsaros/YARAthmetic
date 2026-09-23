rule Valid_Luhn_19
{
    strings:
        $candidate = /[0-9]{19}/

    condition:
        for any i in (1..#candidate) : (
            (
                (uint8(@candidate[i] + 0) - 48) +
                (2 * (uint8(@candidate[i] + 1) - 48) - 9 * ((uint8(@candidate[i] + 1) - 48) \ 5)) +
                (uint8(@candidate[i] + 2) - 48) +
                (2 * (uint8(@candidate[i] + 3) - 48) - 9 * ((uint8(@candidate[i] + 3) - 48) \ 5)) +
                (uint8(@candidate[i] + 4) - 48) +
                (2 * (uint8(@candidate[i] + 5) - 48) - 9 * ((uint8(@candidate[i] + 5) - 48) \ 5)) +
                (uint8(@candidate[i] + 6) - 48) +
                (2 * (uint8(@candidate[i] + 7) - 48) - 9 * ((uint8(@candidate[i] + 7) - 48) \ 5)) +
                (uint8(@candidate[i] + 8) - 48) +
                (2 * (uint8(@candidate[i] + 9) - 48) - 9 * ((uint8(@candidate[i] + 9) - 48) \ 5)) +
                (uint8(@candidate[i] + 10) - 48) +
                (2 * (uint8(@candidate[i] + 11) - 48) - 9 * ((uint8(@candidate[i] + 11) - 48) \ 5)) +
                (uint8(@candidate[i] + 12) - 48) +
                (2 * (uint8(@candidate[i] + 13) - 48) - 9 * ((uint8(@candidate[i] + 13) - 48) \ 5)) +
                (uint8(@candidate[i] + 14) - 48) +
                (2 * (uint8(@candidate[i] + 15) - 48) - 9 * ((uint8(@candidate[i] + 15) - 48) \ 5)) +
                (uint8(@candidate[i] + 16) - 48) +
                (2 * (uint8(@candidate[i] + 17) - 48) - 9 * ((uint8(@candidate[i] + 17) - 48) \ 5)) +
                (uint8(@candidate[i] + 18) - 48)
            ) % 10 == 0
        )
}
