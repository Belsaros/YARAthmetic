from pathlib import Path

from yarithmetic.generators.luhn import generate_luhn16_rule


def main() -> None:
    output_dir = Path("generated")
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / "luhn16.yar"
    output_path.write_text(
        generate_luhn16_rule(),
        encoding="utf-8",
    )

    print(f"Generated {output_path}")


if __name__ == "__main__":
    main()
