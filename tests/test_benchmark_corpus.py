import json
import random

from yarithmetic.benchmark.corpus import (
        category_rng,
        encode_bech32,
        generate_corpus,
        generate_data,
        generate_hrp,
        mutate_bech32,
)
from yarithmetic.reference.bech32 import (
        BECH32_CONSTANT,
        BECH32M_CONSTANT,
        validate_bech32,
        validate_bech32m,
)


def test_generate_corpus_creates_manifest(tmp_path):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest_path = tmp_path / "manifest.json"

    assert manifest_path.exists()

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )
    
    assert manifest["version"] == 1
    assert manifest["seed"] == 20260924
    assert "files" in manifest

def test_generate_corpus_creates_negative_clean_file(tmp_path):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries["negative-clean/0000.txt"]

    assert entry["expected"] == []

    corpus_path = tmp_path / entry["path"]

    assert corpus_path.exists()
    assert corpus_path.stat().st_size == entry["size"]
    assert corpus_path.stat().st_size > 0

def test_generate_corpus_is_reproducible(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"

    generate_corpus(
        first,
        seed=20260924,
    )
    generate_corpus(
        second,
        seed=20260924,
    )

    assert (
        first / "negative-clean" / "0000.txt"
    ).read_bytes() == (
        second / "negative-clean" / "0000.txt"
    ).read_bytes()

    assert (
        first / "manifest.json"
    ).read_bytes() == (
        second / "manifest.json"
    ).read_bytes()

def test_generate_corpus_creates_positive_sparse_file(tmp_path):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries["positive-sparse/0000.txt"]

    assert len(entry["expected"]) == 1

    expected = entry["expected"][0]

    assert expected["value"] == "A12UEL5L"
    assert expected["encoding"] == "bech32"
    assert validate_bech32(expected["value"])

    corpus_path = tmp_path / entry["path"]
    content = corpus_path.read_bytes()

    value = expected["value"].encode("ascii")
    offset = expected["offset"]

    assert content[offset:offset + len(value)] == value
    assert entry["size"] == len(content)

def test_generate_corpus_creates_negative_nearmiss_file(tmp_path):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries["negative-nearmiss/0000.txt"]

    assert entry["expected"] == []

    corpus_path = tmp_path / entry["path"]
    content = corpus_path.read_text(encoding="utf-8")

    value = "A12UEL5M"

    assert value in content
    assert not validate_bech32(value)
    assert not validate_bech32m(value)
    assert entry["size"] == len(content.encode("utf-8"))

def test_encode_bech32_known_vector():
    value = encode_bech32(
        "A",
        [],
        BECH32_CONSTANT,
    )

    assert value == "A12UEL5L"
    assert validate_bech32(value)
    assert not validate_bech32m(value)

def test_encode_bech32m_known_vector():
    value = encode_bech32(
        "A",
        [],
        BECH32M_CONSTANT,
    )

    assert value == "A1LQFN3A"
    assert validate_bech32m(value)
    assert not validate_bech32(value)

def test_generate_data():
    rng = random.Random(20260924)

    data = generate_data(
        rng,
        32,
    )

    assert len(data) == 32
    assert all(
        0 <= value <= 31
        for value in data
    )

def test_encode_generated_bech32_data():
    rng = random.Random(20260924)

    data = generate_data(
        rng,
        32,
    )

    value = encode_bech32(
        "example",
        data,
        BECH32_CONSTANT,
    )

    assert validate_bech32(value)
    assert not validate_bech32m(value)


def test_encode_generated_bech32m_data():
    rng = random.Random(20260924)

    data = generate_data(
        rng,
        32,
    )

    value = encode_bech32(
        "example",
        data,
        BECH32M_CONSTANT,
    )

    assert validate_bech32m(value)
    assert not validate_bech32(value)

def test_generate_corpus_creates_positive_dense_file(tmp_path):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries["positive-dense/0000.txt"]

    assert len(entry["expected"]) == 100

    lengths = {
        len(expected["value"])
        for expected in entry["expected"]
    }

    assert len(lengths) > 1
    assert 8 in lengths
    assert 90 in lengths

    assert any(
        length % 2 == 0
        for length in lengths
    )

    assert any(
        length % 2 == 1
        for length in lengths
    )

    hrps = {
        expected["value"].split("1", 1)[0]
        for expected in entry["expected"]
    }

    assert len(hrps) > 1

    content = (
        tmp_path / entry["path"]
    ).read_bytes()

    for expected in entry["expected"]:
        value = expected["value"]
        encoded = value.encode("ascii")
        offset = expected["offset"]

        assert (
            content[offset:offset + len(encoded)]
            == encoded
        )

        if expected["encoding"] == "bech32":
            assert validate_bech32(value)
            assert not validate_bech32m(value)
        elif expected["encoding"] == "bech32m":
            assert validate_bech32m(value)
            assert not validate_bech32(value)
        else:
            raise AssertionError(
                f"unknown encoding: {expected['encoding']}"
            )

    assert entry["size"] == len(content)

def test_generate_hrp():
    lower_rng = random.Random(20260924)
    upper_rng = random.Random(20260924)

    lower = generate_hrp(
        lower_rng,
        32,
    )
    upper = generate_hrp(
        upper_rng,
        32,
        uppercase=True,
    )

    assert len(lower) == 32
    assert len(upper) == 32

    assert all(
        33 <= ord(char) <= 126
        for char in lower
    )
    assert all(
        33 <= ord(char) <= 126
        for char in upper
    )

    assert lower == lower.lower()
    assert upper == upper.upper()

def test_mutate_bech32_produces_invalid_nearmiss():
    original = "A12UEL5L"

    mutated = mutate_bech32(original)

    assert mutated != original
    assert len(mutated) == len(original)

    separator = original.rfind("1")

    assert mutated[:separator + 1] == original[:separator + 1]

    assert not validate_bech32(mutated)
    assert not validate_bech32m(mutated)

def test_generate_corpus_creates_negative_nearmiss_dense_file(
    tmp_path,
):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries[
        "negative-nearmiss-dense/0000.txt"
    ]

    assert entry["expected"] == []

    content = (
        tmp_path / entry["path"]
    ).read_text(encoding="utf-8")

    values = content.splitlines()

    assert len(values) == 100

    positive_entry = entries[
        "positive-dense/0000.txt"
    ]

    positive_values = [
        expected["value"]
        for expected in positive_entry["expected"]
    ]

    assert len(positive_values) == len(values)

    for original, mutated in zip(
        positive_values,
        values,
    ):
        assert len(mutated) == len(original)

        separator = original.rfind("1")

        assert (
            mutated[:separator + 1]
            == original[:separator + 1]
        )

        differences = sum(
            left != right
            for left, right in zip(
                original,
                mutated,
            )
        )

        assert differences == 1

        assert not validate_bech32(mutated)
        assert not validate_bech32m(mutated)

    assert entry["size"] == len(
        content.encode("utf-8")
    )

def test_generate_corpus_creates_adversarial_file(tmp_path):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries["adversarial/0000.txt"]

    assert entry["expected"] == []

    content = (
        tmp_path / entry["path"]
    ).read_text(encoding="utf-8")

    values = content.splitlines()

    assert len(values) == 2

    for value in values:
        assert len(value) == 90
        assert not validate_bech32(value)
        assert not validate_bech32m(value)

    separators = [
        value.rfind("1")
        for value in values
    ]

    assert separators == [
        83,
        1,
    ]

    assert entry["size"] == len(
        content.encode("utf-8")
    )

def test_category_rng_is_deterministic_and_independent():
    first = category_rng(
        20260924,
        "positive-dense",
    )
    second = category_rng(
        20260924,
        "positive-dense",
    )
    other = category_rng(
        20260924,
        "adversarial",
    )

    first_values = [
        first.randrange(2**32)
        for _ in range(10)
    ]
    second_values = [
        second.randrange(2**32)
        for _ in range(10)
    ]
    other_values = [
        other.randrange(2**32)
        for _ in range(10)
    ]

    assert first_values == second_values
    assert first_values != other_values

def test_generate_corpus_creates_adversarial_candidate_storm(
    tmp_path,
):
    generate_corpus(
        tmp_path,
        seed=20260924,
    )

    manifest = json.loads(
        (tmp_path / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    entries = {
        entry["path"]: entry
        for entry in manifest["files"]
    }

    entry = entries["adversarial/0001.txt"]

    assert entry["expected"] == []

    content = (
        tmp_path / entry["path"]
    ).read_bytes()

    values = content.splitlines()

    assert len(values) > 1000

    for value in values:
        assert len(value) == 90

        decoded = value.decode("ascii")

        assert not validate_bech32(decoded)
        assert not validate_bech32m(decoded)

    assert len(content) >= 100 * 1024
    assert entry["size"] == len(content)
