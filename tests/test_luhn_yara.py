import json
import pytest
import os
import subprocess

from yarithmetic.generators.luhn import generate_luhn_rule
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "tests" / "samples" / "luhn"
VECTORS = ROOT / "tests" / "vectors" / "luhn.json"
YARA = os.environ.get("YARA", "yara")

@pytest.fixture(scope="session", autouse=True)
# def report_yara_version():
#     result = subprocess.run(
#         [YARA, "--version"],
#         capture_output=True,
#         text=True,
#         check=True,
#     )
#     print(f"\nTesting with YARA {result.stdout.strip()}")

def load_vectors():
    with VECTORS.open(encoding="utf-8") as fh:
        return json.load(fh)["vectors"]

def run_generated_rule(tmp_path, sample_path, length=16):
    rule_source = generate_luhn_rule(length)

    rule_path = tmp_path / f"luhn{length}.yar"
    rule_path.write_text(rule_source, encoding="utf-8")

    return subprocess.run(
        [YARA, str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )


def test_generated_luhn_rule_matches_valid_sample(tmp_path):
    result = run_generated_rule(tmp_path, SAMPLES / "valid.txt")

    assert result.returncode == 0, result.stderr
    assert "Valid_Luhn" in result.stdout

def test_generated_luhn_rules_compile(tmp_path):
    for length in (14, 15, 16, 19):
        rule_path = tmp_path / f"luhn{length}.yar"
        rule_path.write_text(
            generate_luhn_rule(length),
            encoding="utf-8",
        )

        result = subprocess.run(
            [YARA, str(rule_path), "/dev/null"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Luhn {length} failed to compile:\n{result.stderr}"
        )

def test_committed_luhn_rules_are_current():
    for length in (14, 15, 16, 19):
        generated_path = ROOT / "generated" / f"luhn{length}.yar"

        assert (
            generated_path.read_text(encoding="utf-8")
            == generate_luhn_rule(length)
        ), f"generated/luhn{length}.yar is stale"

def test_generated_luhn_rule_rejects_invalid_sample(tmp_path):
    result = run_generated_rule(tmp_path, SAMPLES / "invalid.txt")

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_luhn_rule_matches_when_any_candidate_is_valid(tmp_path):
    result = run_generated_rule(tmp_path, SAMPLES / "mixed.txt")

    assert result.returncode == 0, result.stderr
    assert "Valid_Luhn" in result.stdout

def test_generated_luhn_rules_match_vectors(tmp_path, load_vectors):
    for vector in load_vectors:
        value = vector["value"]
        length = len(value)

        rule_path = ROOT / "generated" / f"luhn{length}.yar"
        rule_name = f"Valid_Luhn_{length}"

        sample_path = tmp_path / "candidate.txt"
        sample_path.write_text(value, encoding="ascii")

        result = subprocess.run(
            [YARA, str(rule_path), str(sample_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr

        matched = rule_name in result.stdout

        assert matched is vector["valid"], (
            f'{vector["description"]}: '
            f'{value} expected {vector["valid"]}, '
            f"YARA returned {matched}"
        )

@pytest.mark.parametrize(
    ("sample_name", "length"),
    [
        ("formatted-19.txt", 19),
        ("formatted.txt", 16),
        ("formatted-hyphen.txt", 16),
        ("formatted-mixed.txt", 16),
        ("formatted-15.txt", 15),
        ("formatted-14.txt", 14),
    ],
)
def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
    result = run_generated_rule(
        tmp_path,
        SAMPLES / sample_name,
        length=length,
    )

    assert result.returncode == 0, result.stderr
    assert f"Valid_Luhn_{length}" in result.stdout

def test_generated_luhn_rule_rejects_embedded_candidate(tmp_path):
    result = run_generated_rule(
        tmp_path,
        SAMPLES / "embedded.txt",
        length=16,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

@pytest.mark.parametrize(
    "value",
    [
        "94111111111111111",  # digit immediately before
        "41111111111111119",  # digit immediately after
        "941111111111111119", # digits on both sides
    ],
)
def test_generated_luhn_rule_rejects_digit_embedded_candidate(
    tmp_path,
    value,
):
    sample_path = tmp_path / "embedded.txt"
    sample_path.write_text(value, encoding="ascii")

    result = run_generated_rule(
        tmp_path,
        sample_path,
        length=16,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

@pytest.mark.parametrize(
    "value",
    [
        "x4111111111111111",
        "4111111111111111y",
        "x4111111111111111y",
    ],
)
def test_generated_luhn_rule_allows_nondigit_boundaries(
    tmp_path,
    value,
):
    sample_path = tmp_path / "bounded.txt"
    sample_path.write_text(value, encoding="ascii")

    result = run_generated_rule(
        tmp_path,
        sample_path,
        length=16,
    )

    assert result.returncode == 0, result.stderr
    assert "Valid_Luhn_16" in result.stdout
