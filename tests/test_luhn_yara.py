import subprocess

from yarithmetic.generators.luhn import generate_luhn16_rule

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
