"""Small CLI differences between classic YARA releases."""

from functools import lru_cache
import subprocess


@lru_cache(maxsize=1)
def compiled_options():
    """Older engines auto-detect compiled rules and do not accept -C."""
    result = subprocess.run(["yara", "--help"], capture_output=True, text=True)
    help_text = result.stdout + result.stderr
    # 3.4 prints valid help but exits with status 1.
    if "Usage:" not in help_text:
        raise RuntimeError(f"could not inspect YARA CLI: {help_text.strip()}")
    return ["-C"] if "--compiled-rules" in help_text else []
