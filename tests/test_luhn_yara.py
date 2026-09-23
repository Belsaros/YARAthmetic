import subprocess

from yarithmetic.generators.luhn import generate_luhn16_rule
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "tests" / "samples" / "luhn16"


def run_generated_rule(tmp_path, sample_path):
    rule_source = generate_luhn16_rule()

    rule_path = tmp_path / "luhn16.yar"
    rule_path.write_text(rule_source, encoding="utf-8")

    return subprocess.run(
        ["yara", str(rule_path), str(sample_path)],
        capture_output=True,
        text=True,
    )


def test_generated_luhn_rule_matches_valid_sample(tmp_path):
    result = run_generated_rule(tmp_path, SAMPLES / "valid.txt")

    assert result.returncode == 0, result.stderr
    assert "Valid_Luhn_16" in result.stdout

def test_generated_luhn_rule_compiles(tmp_path):
    rule_source = generate_luhn16_rule()

    rule_path = tmp_path / "luhn16.yar"
    rule_path.write_text(rule_source, encoding="utf-8")

    result = subprocess.run(
        ["yara", "-w", str(rule_path), "/dev/null"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

def test_generated_luhn_rule_rejects_invalid_sample(tmp_path):
    result = run_generated_rule(tmp_path, SAMPLES / "invalid.txt")

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""

def test_generated_luhn_rule_matches_when_any_candidate_is_valid(tmp_path):
    result = run_generated_rule(tmp_path, SAMPLES / "mixed.txt")

    assert result.returncode == 0, result.stderr
    assert "Valid_Luhn_16" in result.stdout
