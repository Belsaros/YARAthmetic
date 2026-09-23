from pathlib import Path

from yarithmetic.generators.luhn import generate_luhn_rule


def main() -> None:
    output_dir = Path("generated")
    output_dir.mkdir(exist_ok=True)

    for length in (14, 15, 16, 19):
        output_path = output_dir / f"luhn{length}.yar"
        output_path.write_text(
            generate_luhn_rule(length),
            encoding="utf-8",
        )

        print(f"Generated {output_path}")


if __name__ == "__main__":
    main()
