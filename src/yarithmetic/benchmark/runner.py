import json
import os
import subprocess
from pathlib import Path
from dataclasses import dataclass
from yarithmetic.benchmark.corpus import generate_corpus
from yarithmetic.generators.bech32 import generate_bech32_rule

@dataclass
class Workspace:
    corpus_path: Path
    manifest_path: Path
    rule_path: Path
    compiled_rule_path: Path

def get_yara_version():
    result = subprocess.run(
        ["yara", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()

def get_cpu_model():
    with open(
        "/proc/cpuinfo",
        encoding="utf-8",
    ) as cpuinfo:
        for line in cpuinfo:
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()

    return "unknown"

def benchmark_workspace(workspace):
    manifest = json.loads(
        workspace.manifest_path.read_text(
            encoding="utf-8",
        )
    )

    correctness = benchmark_correctness(
        workspace.compiled_rule_path,
        workspace.corpus_path,
        manifest,
    )

    scan = measure_compiled_yara(
        workspace.compiled_rule_path,
        workspace.corpus_path,
    )

    corpus_files = [
        path
        for path in workspace.corpus_path.rglob("*")
        if path.is_file()
        and path != workspace.manifest_path
    ]

    file_metrics = {}

    for path in sorted(corpus_files):
        relative_path = path.relative_to(
            workspace.corpus_path
        ).as_posix()

        measurement = measure_compiled_yara(
            workspace.compiled_rule_path,
            path,
        )

        file_metrics[relative_path] = {
            "bytes": path.stat().st_size,
            **measurement,
        }

    return {
        "version": 1,
        "environment": {
            "yara_version": get_yara_version(),
            "cpu_model": get_cpu_model(),
        },
        "artifacts": {
            "source_bytes": workspace.rule_path.stat().st_size,
            "compiled_bytes": workspace.compiled_rule_path.stat().st_size,
        },
        "corpus": {
            "seed": manifest["seed"],
            "files": len(corpus_files),
            "bytes": sum(
                path.stat().st_size
                for path in corpus_files
            ),
        },
        "correctness": correctness,
        "scan": scan,
        "files": file_metrics,
    }

def measure_compiled_yara(
    compiled_rule_path,
    target_path,
):
    marker = "__YARATHMETIC_METRICS__"

    result = subprocess.run(
        [
            "/usr/bin/time",
            "-f",
            f"{marker}%e|%U|%S|%M",
            "yara",
            "-C",
            "-r",
            str(compiled_rule_path),
            str(target_path),
        ],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LC_ALL": "C",
        },
    )

    metrics_line = next(
        line
        for line in result.stderr.splitlines()
        if line.startswith(marker)
    )

    wall, user, system, max_rss = (
        metrics_line.removeprefix(marker).split("|")
    )

    return {
        "returncode": result.returncode,
        "wall_seconds": float(wall),
        "user_seconds": float(user),
        "system_seconds": float(system),
        "max_rss_kib": int(max_rss),
    }

def prepare_workspace(
    output_path,
    *,
    seed,
    shapes=None,
):
    output_path = Path(output_path)

    corpus_path = output_path / "corpus"
    manifest_path = corpus_path / "manifest.json"
    rule_path = output_path / "bech32.yar"
    compiled_rule_path = output_path / "bech32.yarc"

    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    generate_corpus(
        corpus_path,
        seed=seed,
    )

    rule_path.write_text(
        generate_bech32_rule(
            shapes=shapes,
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "yarac",
            str(rule_path),
            str(compiled_rule_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    return Workspace(
        corpus_path=corpus_path,
        manifest_path=manifest_path,
        rule_path=rule_path,
        compiled_rule_path=compiled_rule_path,
    )

def benchmark_correctness(
    compiled_rule_path,
    corpus_path,
    manifest,
):
    matched_paths = run_compiled_yara(
        compiled_rule_path,
        corpus_path,
    )

    return classify_results(
        manifest,
        matched_paths,
    )

def write_metrics(
    metrics_path,
    metrics,
):
    Path(metrics_path).write_text(
        json.dumps(
            metrics,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

def classify_results(manifest, matched_paths):
    result = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
    }

    for entry in manifest["files"]:
        expected = bool(entry["expected"])
        observed = entry["path"] in matched_paths

        if expected and observed:
            result["true_positive"] += 1
        elif not expected and not observed:
            result["true_negative"] += 1
        elif not expected and observed:
            result["false_positive"] += 1
        else:
            result["false_negative"] += 1

    return result

def run_yara(rule_path, corpus_path):
    result = subprocess.run(
        [
            "yara",
            "-r",
            str(rule_path),
            str(corpus_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    matched_paths = set()

    for line in result.stdout.splitlines():
        _, path = line.split(" ", 1)

        matched_paths.add(
            str(
                Path(path).relative_to(
                    corpus_path
                )
            )
        )

    return matched_paths

def run_compiled_yara(
    compiled_rule_path,
    corpus_path,
):
    result = subprocess.run(
        [
            "yara",
            "-C",
            "-r",
            str(compiled_rule_path),
            str(corpus_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    matched_paths = set()

    for line in result.stdout.splitlines():
        _, path = line.split(" ", 1)

        matched_paths.add(
            str(
                Path(path).relative_to(
                    corpus_path,
                )
            )
        )

    return matched_paths
