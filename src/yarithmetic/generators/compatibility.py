"""Generation-time workarounds for classic YARA release differences."""

import re


def parse_output_version(value):
    """Accept a classic YARA major.minor[.patch] target, or preserve defaults."""
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value):
        raise ValueError("output_version must be major.minor or major.minor.patch")
    version = tuple(map(int, value.split(".")))
    version += (0,) * (3 - len(version))
    if version < (3, 4, 0) or version[0] not in (3, 4):
        raise ValueError("output_version must target classic YARA 3.4 or later (3.x or 4.x)")
    return version


def require_match_lengths(output_version):
    version = parse_output_version(output_version)
    if version is not None and version < (3, 5, 0):
        raise ValueError("this generator requires YARA 3.5 or later for match lengths")


def repeat_atom(atom, minimum, maximum, output_version=None):
    """Avoid counted character-class repetition on YARA 3.6.x.

    On 3.6.3, /[0-9]{16}/ can report a length of 17 on a 17-digit input.
    Explicit atoms preserve the intended match lengths and boundary checks.
    maximum=None denotes an unbounded repetition.
    """
    version = parse_output_version(output_version)
    if version is not None and version[:2] == (3, 6):
        if maximum is None:
            return atom * minimum + atom + "*"
        return atom * minimum + (atom + "?") * (maximum - minimum)
    if maximum == minimum:
        return f"{atom}{{{minimum}}}"
    return f"{atom}{{{minimum},{'' if maximum is None else maximum}}}"


def require_runtime_candidate_selection(output_version):
    version = parse_output_version(output_version)
    if version is not None and version < (3, 5, 0):
        raise ValueError(
            "runtime candidate selection requires YARA 3.5 or later; "
            "use the fixed-slot Base58Check generator for YARA 3.4"
        )
