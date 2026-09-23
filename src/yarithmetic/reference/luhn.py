def validate_luhn16(value: str) -> bool:
    """Return True if value is a valid 16-digit Luhn number."""

    if len(value) != 16 or not value.isascii() or not value.isdigit():
        return False

    total = 0

    for index, char in enumerate(value):
        digit = int(char)

        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0
