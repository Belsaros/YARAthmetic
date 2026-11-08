"""Targeted rule generation is checked behaviorally on each matrix engine."""

from pathlib import Path
import subprocess
import sys

import pytest

from yara_support import OUTPUT_VERSION
from yarithmetic.generators.compatibility import parse_output_version
from yarithmetic.generators.luhn import generate_luhn_rule
from yarithmetic.generators.base58 import (
    generate_base58_candidate_rule, generate_base58check_p2pkh_parameterized_rule,
)
from yarithmetic.generators.bech32 import generate_bech32_rule

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("value", ["", "3", "v3.6.3", "3.6.3.1", "3.3.0", "5.0", 365])
def test_invalid_output_versions(value):
    with pytest.raises(ValueError):
        generate_luhn_rule(16, output_version=value)


@pytest.mark.parametrize("version", ["3.4", "3.5.0", "3.6.3", "3.8.1", "3.11.0", "4.0.5", "4.1.3", "4.2.3", "4.5.2"])
def test_luhn_targets_preserve_boundary_behavior(version, tmp_path):
    source = generate_luhn_rule(16, output_version=version)
    rule = tmp_path / "luhn.yar"
    rule.write_text(source)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    values = ["4111111111111111", "41111111111111119", "94111111111111111",
              "4111 1111-1111 1111", "4111 1111 1111 11119", "4111111111111112"]
    for i, value in enumerate(values):
        (corpus / str(i)).write_text(value)
    # The local run checks every target; matrix runs check the selected target.
    if OUTPUT_VERSION is not None and parse_output_version(version) != parse_output_version(OUTPUT_VERSION):
        pytest.skip("behavior is checked on the matching engine in the version matrix")
    result = subprocess.run(["yara", "-r", str(rule), str(corpus)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert {Path(line.split(" ", 1)[1]).name for line in result.stdout.splitlines()} == {"0", "3"}


def test_unsupported_34_generators_fail_explicitly():
    for generator in (generate_bech32_rule, generate_base58check_p2pkh_parameterized_rule):
        with pytest.raises(ValueError, match="3.5 or later"):
            generator(output_version="3.4.0")


def test_main_cli_target_and_output_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "yarithmetic", "--kind", "luhn", "--output_version", "3.6.3",
         "--output-dir", str(tmp_path)], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "luhn16.yar").read_text() == generate_luhn_rule(16, output_version="3.6.3")


def test_base58_cli_target(tmp_path):
    output = tmp_path / "candidate.yar"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/generate-base58"), "--kind", "candidate",
         "--output_version", "3.6.3", "--output", str(output)], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text() == generate_base58_candidate_rule(output_version="3.6.3")


@pytest.mark.parametrize("entry", [["-m", "yarithmetic"], [str(ROOT / "tools/generate-base58"), "--kind", "candidate"]])
def test_cli_invalid_target_does_not_write_output(entry, tmp_path):
    output = tmp_path / "absent"
    destination = ["--output-dir", str(output)] if entry[0] == "-m" else ["--output", str(output)]
    result = subprocess.run([sys.executable, *entry, "--output_version", "invalid", *destination], capture_output=True, text=True)
    assert result.returncode == 2
    assert "output_version" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("matrix", [False, True])
def test_docker_runner_forwards_target_and_test_arguments(tmp_path, matrix):
    import json
    import os

    log = tmp_path / "commands.jsonl"
    docker = tmp_path / "docker-stub"
    docker.write_text(
        f"#!{sys.executable}\nimport json, sys\n"
        f"with open({str(log)!r}, 'a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    docker.chmod(0o755)
    script = "test-yara-versions" if matrix else "test-yara-version"
    versions = ["3.5.0", "3.6.3"] if matrix else ["3.6.3"]
    result = subprocess.run(
        [str(ROOT / "tools" / script), *versions, "--output_version", "3.5.0", "--", "-k", "example"],
        cwd=ROOT, env={**os.environ, "DOCKER": str(docker)}, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(commands) == len(versions) * 2
    for version, (build, run) in zip(versions, zip(commands[::2], commands[1::2])):
        assert build[0] == "build"
        assert f"YARA_VERSION={version}" in build
        assert run[0] == "run"
        assert "YARA_OUTPUT_VERSION=3.5.0" in run
        assert f"yarithmetic-test:{version}" in run
        assert run[-2:] == ["-k", "example"]
