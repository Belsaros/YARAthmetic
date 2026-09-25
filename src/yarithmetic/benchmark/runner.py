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
