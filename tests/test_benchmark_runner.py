from yara_support import OUTPUT_VERSION

import json
import subprocess
from yarithmetic.benchmark.runner import (
        benchmark_correctness,
        benchmark_workspace,
        classify_results,
        get_cpu_model,
        measure_compiled_yara,
        prepare_workspace,
        run_yara,
        run_compiled_yara,
        write_metrics,
)

def test_benchmark_workspace(tmp_path):
    workspace = prepare_workspace(
        tmp_path / "workspace",
        seed=12345,
        output_version=OUTPUT_VERSION,
        shapes=[(8, 1)],
    )

    metrics = benchmark_workspace(workspace)

    assert metrics["version"] == 1

    assert metrics["correctness"] == {
        "true_positive": 2,
        "true_negative": 5,
        "false_positive": 0,
        "false_negative": 0,
    }

    assert metrics["scan"]["returncode"] == 0
    assert metrics["scan"]["wall_seconds"] >= 0
    assert metrics["scan"]["user_seconds"] >= 0
    assert metrics["scan"]["system_seconds"] >= 0
    assert metrics["scan"]["max_rss_kib"] > 0
    assert metrics["artifacts"] == {
        "source_bytes": workspace.rule_path.stat().st_size,
        "compiled_bytes": workspace.compiled_rule_path.stat().st_size,
    }
    assert metrics["corpus"]["seed"] == 12345
    assert metrics["corpus"]["files"] == 7
    assert metrics["corpus"]["bytes"] > 0
    assert metrics["environment"]["yara_version"]
    assert metrics["environment"]["cpu_model"]
    assert set(metrics["files"]) == {
    "adversarial/0000.txt",
    "adversarial/0001.txt",
    "negative-clean/0000.txt",
    "negative-nearmiss/0000.txt",
    "negative-nearmiss-dense/0000.txt",
    "positive-sparse/0000.txt",
    "positive-dense/0000.txt",
    }

    for relative_path, file_metrics in metrics["files"].items():
        corpus_file = workspace.corpus_path / relative_path

        assert file_metrics["bytes"] == corpus_file.stat().st_size
        assert file_metrics["returncode"] == 0
        assert file_metrics["wall_seconds"] >= 0
        assert file_metrics["user_seconds"] >= 0
        assert file_metrics["system_seconds"] >= 0
        assert file_metrics["max_rss_kib"] > 0

def test_write_metrics(tmp_path):
    metrics_path = tmp_path / "metrics.json"

    metrics = {
        "version": 1,
        "implementation": "bech32",
        "correctness": {
            "true_positive": 2,
            "true_negative": 5,
            "false_positive": 0,
            "false_negative": 0,
        },
    }

    write_metrics(
        metrics_path,
        metrics,
    )

    assert json.loads(
        metrics_path.read_text(
            encoding="utf-8",
        )
        ) == metrics

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
        output_version=OUTPUT_VERSION,
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

def test_measure_compiled_yara(tmp_path):
    rule_path = tmp_path / "test.yar"
    compiled_rule_path = tmp_path / "test.yarc"
    sample_path = tmp_path / "sample.txt"

    rule_path.write_text(
        """
rule Benchmark_Test
{
    condition:
        true
}
""",
        encoding="utf-8",
    )

    sample_path.write_text(
        "hello",
        encoding="ascii",
    )

    subprocess.run(
        [
            "yarac",
            str(rule_path),
            str(compiled_rule_path),
        ],
        check=True,
    )

    metrics = measure_compiled_yara(
        compiled_rule_path,
        sample_path,
    )

    assert metrics["returncode"] == 0
    assert metrics["wall_seconds"] >= 0
    assert metrics["user_seconds"] >= 0
    assert metrics["system_seconds"] >= 0
    assert metrics["max_rss_kib"] > 0
