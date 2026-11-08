import argparse
from pathlib import Path

from yarithmetic.generators.bech32 import generate_bech32_rule
from yarithmetic.generators.luhn import generate_luhn_rule
from yarithmetic.generators.compatibility import parse_output_version, require_match_lengths


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate checksum validation rules.")
    parser.add_argument("--output_version", "--output-version", default=None,
                        help="Target classic YARA version, e.g. 3.6.3")
    parser.add_argument("--output-dir", type=Path, default=Path("generated"))
    parser.add_argument("--kind", choices=("all", "luhn", "bech32"), default="all")
    args = parser.parse_args()
    try:
        parse_output_version(args.output_version)
        if args.kind in ("all", "bech32"):
            require_match_lengths(args.output_version)
    except ValueError as error:
        parser.error(str(error))
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    for length in ((14, 15, 16, 19) if args.kind in ("all", "luhn") else ()):
        output_path = output_dir / f"luhn{length}.yar"
        output_path.write_text(
            generate_luhn_rule(length, output_version=args.output_version),
            encoding="utf-8",
        )

        print(f"Generated {output_path}")

    if args.kind == "luhn":
        return

    output_path = output_dir / "bech32.yar"
    output_path.write_text(generate_bech32_rule(output_version=args.output_version), encoding="utf-8")
    print(f"Generated {output_path}")


if __name__ == "__main__":
    main()
