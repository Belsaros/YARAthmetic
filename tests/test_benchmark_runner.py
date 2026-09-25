import subprocess
from yarithmetic.benchmark.runner import (
        benchmark_correctness,
        classify_results,
        prepare_workspace,
        run_yara,
        run_compiled_yara,
)

def test_benchmark_correctness(tmp_path):
    rule_path = tmp_path / "test.yar"
    compiled_rule_path = tmp_path / "test.yarc"
    corpus_path = tmp_path / "corpus"

    corpus_path.mkdir()

    rule_path.write_text(
        """
rule Benchmark_Test
{
    strings:
        $needle = "VALID_STRING"

    condition:
        $needle
}
""",
        encoding="utf-8",
    )

    subprocess.run(
        [
            "yarac",
            str(rule_path),
            str(compiled_rule_path),
        ],
        check=True,
    )

    files = {
        "positive-1.txt": "VALID_STRING",
        "positive-2.txt": "prefix VALID_STRING suffix",
        "negative-1.txt": "ordinary text",
        "negative-2.txt": "nothing interesting",
    }

    for path, content in files.items():
        (corpus_path / path).write_text(
            content,
            encoding="utf-8",
        )

    manifest = {
        "files": [
            {
                "path": "positive-1.txt",
                "expected": [{"value": "VALID_STRING"}],
            },
            {
                "path": "positive-2.txt",
                "expected": [{"value": "VALID_STRING"}],
            },
            {
                "path": "negative-1.txt",
                "expected": [],
            },
            {
                "path": "negative-2.txt",
                "expected": [],
            },
        ],
    }

    result = benchmark_correctness(
        compiled_rule_path,
        corpus_path,
        manifest,
    )

    assert result == {
        "true_positive": 2,
        "true_negative": 2,
        "false_positive": 0,
        "false_negative": 0,
    }

def test_classify_results():
    manifest = {
        "files": [
            {
                "path": "positive.txt",
                "expected": [
                    {
                        "offset": 42,
                        "value": "A12UEL5L",
                        "encoding": "bech32",
                    },
                ],
            },
            {
                "path": "true-negative.txt",
                "expected": [],
            },
            {
                "path": "false-positive.txt",
                "expected": [],
            },
            {
                "path": "false-negative.txt",
                "expected": [
                    {
                        "offset": 17,
                        "value": "A1LQFN3A",
                        "encoding": "bech32m",
                    },
                ],
            },
        ],
    }

    matched_paths = {
        "positive.txt",
        "false-positive.txt",
    }

    result = classify_results(
        manifest,
        matched_paths,
    )

    assert result == {
        "true_positive": 1,
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1,
    }

def test_run_yara_returns_matching_relative_paths(
    tmp_path,
):
    rule_path = tmp_path / "test.yar"
    corpus_path = tmp_path / "corpus"

    corpus_path.mkdir()

    rule_path.write_text(
        """
rule Benchmark_Test
{
    strings:
        $needle = "VALID_STRING"

    condition:
        $needle
}
""",
        encoding="utf-8",
    )

    (corpus_path / "positive.txt").write_text(
        "There is a VALID_STRING in this corpus.",
        encoding="utf-8",
    )

    (corpus_path / "negative.txt").write_text(
        "There are no valid strings in this corpus.",
        encoding="utf-8",
    )

    matched_paths = run_yara(
        rule_path,
        corpus_path,
    )

    assert matched_paths == {
        "positive.txt",
    }

def test_prepare_workspace_creates_expected_paths(tmp_path):
    workspace = prepare_workspace(
        tmp_path,
        seed=12345,
        shapes=[(8, 1)],
    )

    assert workspace.corpus_path == tmp_path / "corpus"
    assert workspace.manifest_path == tmp_path / "corpus" / "manifest.json"
    assert workspace.rule_path == tmp_path / "bech32.yar"
    assert workspace.compiled_rule_path == tmp_path / "bech32.yarc"

    assert workspace.manifest_path.is_file()
    assert workspace.rule_path.is_file()
    assert workspace.compiled_rule_path.is_file()

def test_run_compiled_yara(tmp_path):
    rule_path = tmp_path / "test.yar"
    compiled_rule_path = tmp_path / "test.yarc"
    corpus_path = tmp_path / "corpus"

    corpus_path.mkdir()

    rule_path.write_text(
        """
rule Benchmark_Test
{
    strings:
        $needle = "VALID_STRING"

    condition:
        $needle
}
""",
        encoding="utf-8",
    )

    (corpus_path / "positive.txt").write_text(
        "before VALID_STRING after",
        encoding="utf-8",
    )

    subprocess.run(
        [
            "yarac",
            str(rule_path),
            str(compiled_rule_path),
        ],
        check=True,
    )

    matched_paths = run_compiled_yara(
        compiled_rule_path,
        corpus_path,
    )

    assert matched_paths == {
        "positive.txt",
    }
