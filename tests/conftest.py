"""Version-matrix exclusions for generators requiring match-length syntax."""

from pathlib import Path

import pytest

from yarithmetic.generators.compatibility import parse_output_version
from yara_support import OUTPUT_VERSION


def pytest_collection_modifyitems(items):
    target = parse_output_version(OUTPUT_VERSION)
    if target is None or target >= (3, 5, 0):
        return
    for item in items:
        filename = Path(str(item.fspath)).name
        name = item.originalname
        requires_lengths = (
            filename == "test_bech32_compact.py"
            and name not in ("test_committed_rule_is_current", "test_packed_lookup_every_index_and_transition_constants")
        ) or (
            filename == "test_bech32_yara.py"
            and (name.startswith("test_generated_bech32_rule_") or name in (
                "test_generated_rule_accepts_bech32m",
                "test_yara_loop_range_can_depend_on_runtime_length",
            ))
        ) or (
            filename == "test_benchmark_runner.py"
            and name in ("test_benchmark_workspace", "test_prepare_workspace_creates_expected_paths")
        )
        if requires_lengths:
            item.add_marker(pytest.mark.skip(reason="this generator requires match lengths (YARA >= 3.5)"))
