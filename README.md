# YARAthmetic

**Generated validation algorithms implemented entirely in YARA.**

YARAthmetic is an experiment in pushing YARA beyond pattern matching.

Many structured identifiers can be recognized approximately with regular expressions, but recognizing a string that *looks like* an identifier is not the same as determining that it is valid. Credit card numbers, cryptocurrency addresses, and other structured values may include checksums or other mathematical constraints that dramatically reduce false positives.

YARAthmetic generates self-contained YARA rules that perform those validations using YARA's own condition language.

The generated rules may be ugly.

The generator doesn't have to be.

## Goals

YARAthmetic aims to:

* Generate self-contained YARA rules for algorithmically validated data.
* Require no Python, Perl, external validator, or callback at scan time.
* Separate human-readable generator code from machine-generated YARA.
* Validate candidates rather than merely matching their textual shape.
* Test generated rules against authoritative public test vectors.
* Test compatibility across multiple YARA versions.
* Make unreasonable but technically valid uses of YARA easier to maintain.

The fundamental runtime constraint is:

```text
input
  |
  v
YARA + generated rules
  |
  v
validated detection
```

Python may be used to generate rules and test them, but it is not part of runtime detection.

## Project Status

YARAthmetic is experimental and under active development.

Initial targets include:

* Luhn checksum validation
* Bech32
* Bech32m
* Base58Check: an experimental Boolean-circuit implementation validates a
  restricted P2PKH address format and one candidate slot per circuit. See
  [Base58 feasibility](BASE58.md) for coverage, measurements, and generation commands.

Bech32/Bech32m now uses shared checksum arithmetic across all 3,486 supported
length/HRP shapes, producing about 254 KB of source instead of 193 MB. It still
checks every candidate occurrence. See [Bech32 implementation](BECH32.md).

Additional validators may be added where they provide interesting or useful demonstrations of algorithmic validation inside YARA.

## Why Generate YARA?

Some algorithms are possible to express in YARA but unpleasant to maintain by hand.

For example, an algorithm involving repeated arithmetic or state transitions may require large unrolled expressions because YARA does not provide the same programming abstractions as a general-purpose language.

YARAthmetic treats those rules as generated artifacts.

Human-maintained code describes the algorithm. The generator emits whatever repetitive YARA is necessary to implement it.

Generated files should therefore be reproducible and should not normally be edited manually.

## Testing

YARAthmetic is developed test-first.

Tests should cover several layers:

1. Reference implementations against authoritative public test vectors.
2. Generator behavior.
3. Compilation of generated rules.
4. Behavioral agreement between reference implementations and generated YARA.
5. Valid, invalid, malformed, truncated, and mutated inputs.
6. Compatibility with supported YARA versions.

A generated rule compiling successfully is not sufficient. It must produce the expected results.

Where practical, tests should perform differential validation:

```text
test vector
    |
    +----> reference implementation ----> expected result
    |
    +----> generated YARA --------------> actual result

                    expected == actual
```

## Repository Layout

The intended layout is approximately:

```text
YARAthmetic/
├── LICENSE
├── README.md
├── pyproject.toml
├── src/
│   └── yarithmetic/
├── generated/
├── tests/
│   └── vectors/
└── .github/
    └── workflows/
```

This structure may change as the project develops.

## Compatibility

Supported YARA versions will be determined through automated testing rather than assumed from syntax compatibility alone.

Individual validators may have different minimum YARA versions.

Compatibility with old YARA releases is welcome where it occurs naturally, but new development will not necessarily be constrained by legacy versions.

## Provenance

YARAthmetic is an independent, clean-room project.

Implementations and tests should be derived from public specifications, publicly available documentation, and public test vectors.

Do not contribute proprietary detection rules, private test data, confidential implementation details, or other material that you do not have the right to publish.

## Generated Rules

Generated YARA rules are intended to be committed to the repository so that users who only want the resulting rules do not need Python or the generator toolchain.

The generated files are part of the distributable output of the project.

Each generated file should clearly identify itself as generated and identify the generator responsible for producing it.

## Contributing

Contributions, additional validators, compatibility improvements, test vectors, and particularly creative abuses of YARA are welcome.

Generated output should be accompanied by tests demonstrating correct behavior.

## License

YARAthmetic is released under the MIT License. See `LICENSE` for details.

