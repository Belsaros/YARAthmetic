# Classic YARA compatibility

Rule-generation commands accept `--output_version MAJOR.MINOR[.PATCH]`
(`--output-version` is an alias). Python rule generators accept the keyword
`output_version="3.6.3"`. Omitting the option preserves the existing generated
source; generation does not inspect the installed YARA executable.

Generate into a separate directory to retain the default artifacts:

```sh
PYTHONPATH=src python3 -m yarithmetic --output_version 3.6.3 --output-dir /tmp/yara-3.6.3
PYTHONPATH=src python3 tools/generate-base58 --kind candidate --output_version 3.6.3 --output /tmp/base58-3.6.3.yar
PYTHONPATH=src python3 tools/generate-base58 --kind p2pkh-checksum --output_version 3.4.0 --output /tmp/base58check-3.4.0.yar
PYTHONPATH=src python3 -m yarithmetic --kind luhn --output_version 3.4.0 --output-dir /tmp/yara-3.4.0
```

The target controls `.yar` source generation. Compile with the intended engine;
compiled `.yarc` files are not promised to be portable between releases. Targets
are classic YARA 3.4 and later in the 3.x/4.x families. A syntactically valid
version is a compatibility request, not a claim that every release was tested.

## Generation policies

- **YARA 3.4:** Luhn uses known compact/formatted lengths instead of unsupported
  `!string[index]` syntax. Base58 candidate detection emits private fixed-length
  rules joined by the usual public `Base58_Candidate` rule. Fixed-slot
  Base58Check also works. Bech32 requires match lengths, and parameterized
  Base58Check encounters an external-variable defect; these two generators
  explicitly reject a 3.4 target rather than emitting unreliable rules.
- **YARA 3.6.x:** Counted character-class repetitions are expanded into explicit
  atoms and optional atoms (or a trailing `*` for unbounded repetitions). On
  3.6.3, `/[0-9]{16}/` reports a 17-character first match on
  `41111111111111119`, causing the unmodified Luhn rule to accept an embedded
  candidate. The expanded pattern preserves checksum and boundary semantics.
  The same policy applies to Base58 and Bech32 candidate patterns.
- **Other targets:** Existing source forms are retained where no workaround is
  needed. Validator coverage is unchanged: in particular, Base58Check still
  supports only its documented P2PKH shape and one selected occurrence per scan.

Upstream release tags include 3.6.0 through 3.6.3, with no 3.6.5 tag; the Docker
matrix uses 3.6.3.

## Docker tests

```sh
tools/test-yara-version 3.6.3
tools/test-yara-versions
# Limit the matrix, override output targeting, or forward pytest arguments:
tools/test-yara-versions 3.5.0 3.6.3 -- -q
tools/test-yara-version 3.6.3 --output_version default -- -m luhn
```

The runner targets its engine version automatically through the test-only
`YARA_OUTPUT_VERSION` environment variable. `--output_version default` tests
unmodified default output, useful when reproducing an engine regression. An
explicit numeric override tests that generated dialect on the selected engine.
Tests never regenerate committed files in the read-only source mount. If Docker
requires root, prefix the command with `DOCKER="sudo docker"`.

The image includes GNU `time` for benchmark tests. Dependencies are cached
independently of the selected YARA version. Test and benchmark scan commands
inspect CLI help: older engines auto-detect compiled rules and reject the newer
`-C` flag. Exploratory expressions exceeding an engine's configured loop limit
are skipped; the production compact Bech32 rule uses at most four nested loops.
YARA 3.4 additionally skips validators whose generation policies reject it.

The standalone 55-byte SHA-256 circuit probe triggers a compiler arena assertion
on YARA 3.4.0 and 3.5.0. That exact assertion is recorded as an expected failure
on those targets; other compilation errors still fail. The fixed-slot
Base58Check double-SHA circuits pass independently. Generation targeting does
not claim to repair this standalone compiler defect.

## Verified matrix

The Docker suite checks public vectors, generated values and mutations,
multiple candidate occurrences, boundaries, and all 3,486 Bech32 shapes in both
encodings. The table describes the public generators' documented coverage.
Known unsupported features and standalone compiler probes are handled as
specified above, not counted as supported validation.

| YARA | Luhn | Bech32/Bech32m | Base58 candidates | Fixed-slot Base58Check | Runtime Base58Check |
| --- | --- | --- | --- | --- | --- |
| 3.4.0 | Pass | Requires 3.5 | Pass | Pass | Requires 3.5 |
| 3.5.0 | Pass | Pass | Pass | Pass | Pass |
| 3.6.3 | Pass | Pass | Pass | Pass | Pass |
| 3.8.1 | Pass | Pass | Pass | Pass | Pass |
| 3.11.0 | Pass | Pass | Pass | Pass | Pass |
| 4.0.5 | Pass | Pass | Pass | Pass | Pass |
| 4.1.3 | Pass | Pass | Pass | Pass | Pass |
| 4.2.3 | Pass | Pass | Pass | Pass | Pass |
| 4.5.2 (native) | Pass | Pass | Pass | Pass | Pass |
