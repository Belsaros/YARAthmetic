def validate_luhn(value: str) -> bool:
    """Return True if value passes the Luhn checksum."""

    if not value or not value.isascii() or not value.isdigit():
        return False

    total = 0
    parity = len(value) % 2

    for index, char in enumerate(value):
        digit = int(char)

        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0
