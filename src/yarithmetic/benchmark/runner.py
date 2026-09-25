import subprocess
from pathlib import Path

def benchmark_correctness(
    rule_path,
    corpus_path,
    manifest,
):
    matched_paths = run_yara(
        rule_path,
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
