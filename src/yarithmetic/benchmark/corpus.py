import json
import random

from yarithmetic.reference.bech32 import (
    BECH32_CONSTANT,
    BECH32M_CONSTANT,
    CHARSET,
    hrp_expand,
    polymod,
)

WORDS = [
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "hotel",
    "india",
    "juliet",
    "kilo",
]

def mutate_bech32(value):
    replacement = (
        "q"
        if value[-1].lower() != "q"
        else "p"
    )

    if value.isupper():
        replacement = replacement.upper()

    return value[:-1] + replacement

def generate_hrp(rng, length, *, uppercase=False):
    hrp = "".join(
        chr(rng.randrange(33, 127))
        for _ in range(length)
    )

    if uppercase:
        return hrp.upper()

    return hrp.lower()

def generate_data(rng, length):
    return [
        rng.randrange(32)
        for _ in range(length)
    ]

def generate_text(rng, word_count):
    return " ".join(
        rng.choice(WORDS)
        for _ in range(word_count)
    )

def encode_bech32(hrp, data, constant):
    data = list(data)

    values = hrp_expand(hrp.lower()) + data + [0] * 6
    checksum = polymod(values) ^ constant

    checksum_values = [
        (checksum >> (5 * (5 - position))) & 31
        for position in range(6)
    ]

    encoded_data = "".join(
        CHARSET[value]
        for value in data + checksum_values
    )

    if hrp.isupper():
        encoded_data = encoded_data.upper()

    return hrp + "1" + encoded_data

def category_rng(seed, category):
    return random.Random(
        f"{seed}:{category}"
    )

def generate_corpus(
    output_path,
    *,
    seed: int,
):
    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    negative_clean_rng = category_rng(
        seed,
        "negative-clean",
    )
    positive_sparse_rng = category_rng(
        seed,
        "positive-sparse",
    )
    negative_nearmiss_rng = category_rng(
        seed,
        "negative-nearmiss",
    )
    positive_dense_rng = category_rng(
        seed,
        "positive-dense",
    )
    adversarial_rng = category_rng(
        seed,
        "adversarial",
    )

    negative_clean_path = (
        output_path / "negative-clean" / "0000.txt"
    
    )
    negative_clean_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    text = generate_text(negative_clean_rng, 1024) + "\n"

    negative_clean_path.write_text(
        text,
        encoding="utf-8",
    )

    positive_sparse_path = (
        output_path / "positive-sparse" / "0000.txt"
    )

    positive_sparse_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    prefix = generate_text(positive_sparse_rng, 512) + "\n"
    suffix = "\n" + generate_text(positive_sparse_rng, 512) + "\n"

    sparse_value = "A12UEL5L"

    positive_sparse_text = prefix + sparse_value + suffix

    positive_sparse_path.write_text(
        positive_sparse_text,
        encoding="utf-8",
    )

    positive_sparse_offset = len(
        prefix.encode("utf-8")
    )

    negative_nearmiss_path = (
        output_path / "negative-nearmiss" / "0000.txt"
    )
    negative_nearmiss_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    prefix = generate_text(negative_nearmiss_rng, 512) + "\n"
    suffix = "\n" + generate_text(negative_nearmiss_rng, 512) + "\n"

    nearmiss_value = "A12UEL5M"
    
    negative_nearmiss_text = (
        prefix + nearmiss_value + suffix
    )

    negative_nearmiss_path.write_text(
        negative_nearmiss_text,
        encoding="utf-8",
    )

    positive_dense_path = (
        output_path / "positive-dense" / "0000.txt"
    )
    positive_dense_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    positive_dense_parts = []
    positive_dense_expected = []
    positive_dense_offset = 0

    for index in range(100):
        if index == 99:
            hrp_length = 20
            data_length = 63
        else:
            hrp_length = 1 + (index % 16)
            data_length = (index * 2) % 64

        data = generate_data(
            positive_dense_rng,
            data_length,
        )

        if index % 2 == 0:
            constant = BECH32_CONSTANT
            encoding = "bech32"
        else:
            constant = BECH32M_CONSTANT
            encoding = "bech32m"

        uppercase = index % 4 >= 2

        hrp = generate_hrp(
            positive_dense_rng,
            hrp_length,
            uppercase=uppercase,
        )

        dense_value = encode_bech32(
            hrp,
            data,
            constant,
        )

        line = dense_value + "\n"
        encoded_line = line.encode("ascii")

        positive_dense_parts.append(line)
        positive_dense_expected.append(
            {
                "offset": positive_dense_offset,
                "value": dense_value,
                "encoding": encoding,
            }
        )

        positive_dense_offset += len(encoded_line)

    positive_dense_text = "".join(
        positive_dense_parts
    )

    positive_dense_path.write_text(
        positive_dense_text,
        encoding="utf-8",
    )
   
    negative_nearmiss_dense_path = (
        output_path
        / "negative-nearmiss-dense"
        / "0000.txt"
    )
    negative_nearmiss_dense_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    negative_nearmiss_dense_values = [
        mutate_bech32(expected["value"])
        for expected in positive_dense_expected
    ]

    negative_nearmiss_dense_text = (
        "\n".join(negative_nearmiss_dense_values)
        + "\n"
    )

    negative_nearmiss_dense_path.write_text(
        negative_nearmiss_dense_text,
        encoding="utf-8",
    )

    adversarial_path = (
        output_path / "adversarial" / "0000.txt"
    )
    adversarial_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Maximum HRP, minimum data:
    # 83 HRP + 1 separator + 0 payload + 6 checksum = 90
    hrp_heavy_valid = encode_bech32(
        "a" * 83,
        [],
        BECH32_CONSTANT,
    )

    # Minimum HRP, maximum data:
    # 1 HRP + 1 separator + 82 payload + 6 checksum = 90
    data_heavy_valid = encode_bech32(
        "a",
        generate_data(adversarial_rng, 82),
        BECH32_CONSTANT,
    )

    adversarial_values = [
        mutate_bech32(hrp_heavy_valid),
        mutate_bech32(data_heavy_valid),
    ]

    adversarial_text = (
        "\n".join(adversarial_values)
        + "\n"
    )

    adversarial_path.write_text(
        adversarial_text,
        encoding="utf-8",
    )

    adversarial_storm_path = (
        output_path / "adversarial" / "0001.txt"
    )

    adversarial_storm_values = []
    adversarial_storm_size = 0

    while adversarial_storm_size < 100 * 1024:
        valid = encode_bech32(
            "a",
            generate_data(
                adversarial_rng,
                82,
            ),
            BECH32_CONSTANT,
        )

        mutated = mutate_bech32(valid)

        adversarial_storm_values.append(
            mutated
        )

        adversarial_storm_size += (
            len(mutated.encode("ascii")) + 1
        )

    adversarial_storm_text = (
        "\n".join(adversarial_storm_values)
        + "\n"
    )

    adversarial_storm_path.write_text(
        adversarial_storm_text,
        encoding="utf-8",
    )

    manifest = {
        "version": 1,
        "seed": seed,
        "files": [
            {
                "path": "negative-nearmiss/0000.txt",
                "size": negative_nearmiss_path.stat().st_size,
                "expected": [],
            },
            {
                "path": "negative-clean/0000.txt",
                "size": negative_clean_path.stat().st_size,
                "expected": [],
            },
            {
                "path": "positive-dense/0000.txt",
                "size": positive_dense_path.stat().st_size,
                "expected": positive_dense_expected,
            },
            {
                "path": "adversarial/0000.txt",
                "size": adversarial_path.stat().st_size,
                "expected": [],
            },
            {
                "path": "adversarial/0001.txt",
                "size": adversarial_storm_path.stat().st_size,
                "expected": [],
            },
            {
                "path": "negative-nearmiss-dense/0000.txt",
                "size": negative_nearmiss_dense_path.stat().st_size,
                "expected": [],
            },
            {
                "path": "positive-sparse/0000.txt",
                "size": positive_sparse_path.stat().st_size,
                "expected": [
                    {
                        "offset": positive_sparse_offset,
                        "value": sparse_value,
                        "encoding": "bech32",
                    },
                ],
            },
        ],
    }

    (output_path / "manifest.json").write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
