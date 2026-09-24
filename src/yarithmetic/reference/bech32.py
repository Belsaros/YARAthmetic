CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32_CONSTANT = 1
BECH32M_CONSTANT = 0x2BC830A3

GENERATORS = (
    0x3B6A57B2,
    0x26508E6D,
    0x1EA119FA,
    0x3D4233DD,
    0x2A1462B3,
)

def validate_bech32(value: str) -> bool:
    return validate(value, BECH32_CONSTANT)


def validate_bech32m(value: str) -> bool:
    return validate(value, BECH32M_CONSTANT)

def polymod_step(checksum: int, value: int) -> int:
    top = checksum >> 25
    checksum = ((checksum & 0x1FFFFFF) << 5) ^ value

    for index, generator in enumerate(GENERATORS):
        if (top >> index) & 1:
            checksum ^= generator

    return checksum

def polymod(values: list[int]) -> int:
    checksum = 1

    for value in values:
        checksum = polymod_step(checksum, value)

    return checksum

def hrp_expand(hrp: str) -> list[int]:
    return (
        [ord(char) >> 5 for char in hrp]
        + [0]
        + [ord(char) & 31 for char in hrp]
    )

def decode_data(data: str) -> list[int]:
    return [CHARSET.index(char.lower()) for char in data]

def validate(value: str, constant: int) -> bool:
    if not value or len(value) > 90:
        return False

    if value.lower() != value and value.upper() != value:
        return False

    value = value.lower()

    separator = value.rfind("1")

    if separator < 1:
        return False

    if separator + 7 > len(value):
        return False

    hrp = value[:separator]
    data = value[separator + 1:]

    if any(ord(char) < 33 or ord(char) > 126 for char in hrp):
        return False

    if any(char.lower() not in CHARSET for char in data):
        return False

    values = hrp_expand(hrp) + decode_data(data)

    return polymod(values) == constant
