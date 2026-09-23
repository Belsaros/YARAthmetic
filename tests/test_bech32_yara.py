import subprocess

import pytest

from yarithmetic.generators.bech32 import generate_bech32_rule


pytestmark = pytest.mark.bech32


def test_generated_bech32_rule_matches_candidate(tmp_path):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(generate_bech32_rule(), encoding="utf-8")
    sample_path.write_text(
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        encoding="ascii",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout

def test_generated_bech32_rule_rejects_non_candidate(tmp_path):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(generate_bech32_rule(), encoding="utf-8")
    sample_path.write_text(
        "There is absolutely no encoded data in this file.",
        encoding="ascii",
    )

    result = subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def run_rule(tmp_path, value):
    rule_path = tmp_path / "bech32.yar"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(generate_bech32_rule(), encoding="utf-8")
    sample_path.write_text(value, encoding="ascii")

    return subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )

def test_generated_bech32_rule_rejects_candidate_over_90_characters(tmp_path):
    value = "a" * 83 + "1" + "q" * 7
    assert len(value) == 91

    result = run_rule(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_generated_bech32_rule_allows_90_character_candidate(tmp_path):
    value = "a" * 83 + "1" + "q" * 6
    assert len(value) == 90

    result = run_rule(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert "Bech32_Candidate" in result.stdout
