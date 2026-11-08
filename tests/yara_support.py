"""Shared target selection and CLI capability checks for integration tests."""

import os
from yarithmetic.yara_cli import compiled_options

OUTPUT_VERSION = os.environ.get("YARA_OUTPUT_VERSION") or None
