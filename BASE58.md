# Base58 feasibility

Checksum validation is possible in classic YARA. The experimental generator
decodes Base58 and implements both SHA-256 passes using private YARA rules as
Boolean circuit gates. It needs no imports, callbacks, external variables, or
validator at scan time.

This is an experiment with deliberately narrow coverage, not yet a general
Base58Check detector.

## Supported prototype

`generate_base58check_p2pkh_rule(candidate_index=1)` validates one selected regex
occurrence per file with these properties:

- Bitcoin's Base58 alphabet, case sensitive.
- Exactly 34 characters, beginning with one `1` and then a character other than `1`.
- Exactly 25 decoded bytes: version `0x00`, 20 payload bytes, and four checksum bytes.
- ASCII alphanumeric boundaries.
- Checksum equal to the first four bytes of SHA256(SHA256(version || payload)).

The candidate index counts regex matches, including checksum-invalid and embedded
matches. The default examines only the first occurrence. A valid address after
an invalid first candidate will not be detected by slot 1. Generate a separate
circuit for slot 2, and so on, to cover additional occurrences; source size and
work grow with the number of slots. The current API permits slots 1 through 16.
This does not imply unlimited-candidate detection.

Shorter P2PKH addresses, additional leading zero bytes, P2SH, WIF, extended keys,
and other Base58 alphabets are outside this prototype's coverage. A valid address
checksum also does not demonstrate ownership or activity.

All Base58 generation modes accept `--output_version`, including the
parameterized mode described below. See [compatibility](COMPATABILITY.md).

## Runtime candidate selection

`generate_base58check_p2pkh_parameterized_rule()` generates a separate circuit
whose regex occurrence is selected by the external integer `candidate_index`.
Compile once, then choose a different occurrence for each scan:

```sh
PYTHONPATH=src python3 tools/generate-base58 --kind p2pkh-checksum-parameterized --output /tmp/base58check-runtime.yar
yarac -d candidate_index=1 /tmp/base58check-runtime.yar /tmp/base58check-runtime.yarc
yara -C -d candidate_index=2 /tmp/base58check-runtime.yarc sample.txt
```

Runtime selection requires YARA 3.5 or later; use fixed-slot generation on 3.4.
Define the external as an integer at compilation. If omitted at scan time, its
compiled default applies. Nonpositive indices and indices beyond the candidate
count do not match. Unlike the fixed generator, runtime selection has no
sixteen-slot limit. It still checks only one occurrence per scan, counts embedded
and checksum-invalid regex matches, and has the same address-shape and boundary
restrictions. It requires an external variable; the existing fixed-slot API and
CLI mode remain self-contained and unchanged.

## Why Boolean rules work

Base58 decoding can be expressed as a weighted sum of character values. The
generator splits coefficients into 32-bit columns and propagates carries; each
column sum fits within YARA's signed 64-bit arithmetic for the supported lengths.
The decoder helpers support 1 through 128 characters. Leading `1` characters
represent zero bytes and require separate decoded-length handling.

SHA-256 is nonlinear, so Bech32's symbolic linear expansion does not apply.
Inlining all SHA state transitions would repeatedly duplicate intermediate
expressions. Instead, each private rule computes a Boolean wire once per file,
and subsequent rules reference that result. Binary addition, rotations, message
expansion, and all 128 rounds of double SHA-256 use that shared circuit.

The tradeoff is that a rule cannot accept a candidate offset as a parameter.
The original circuit's inputs therefore reference a fixed regex occurrence; the
parameterized version uses one external index shared by all inputs. General
candidate iteration is the next design problem, along with circuit size and
throughput.

YARA's built-in hash module offers no direct shortcut: it hashes bytes from the
file or a string, and returns hexadecimal text. Nesting `hash.sha256()` hashes
that text rather than the required raw digest. On YARA 4.5.2, probes also reject
string concatenation and integer arguments to `hash.sha256()`.

## Initial measurement

One candidate slot on YARA 4.5.2 in the development environment:

| Measurement | Result |
| --- | ---: |
| Generated source | 27,673,072 bytes |
| Private rules | 219,854 |
| Compiled rule | 40,207,310 bytes |
| Generation | about 0.84 seconds |
| Compilation | about 5.8 seconds |
| One genesis-address scan, including rule loading | about 0.28 seconds |
| Peak resident memory for that scan | 76,592 KiB |

These are initial single-run measurements, not a throughput benchmark or a
compatibility guarantee. The compiler warns about the broad candidate regex.
Large files, candidate storms, and multiple slots still need benchmarking.
Large generated prototype artifacts are produced on demand during exploration.

## Generate and scan

From the repository root, with Python, `yara`, and `yarac` installed:

```sh
PYTHONPATH=src python3 tools/generate-base58 --kind p2pkh-checksum --output /tmp/base58check.yar
yarac /tmp/base58check.yar /tmp/base58check.yarc
yara -C /tmp/base58check.yarc sample.txt
```

For alphabet/length detection only:

```sh
PYTHONPATH=src python3 tools/generate-base58 --kind candidate --output /tmp/base58-candidates.yar
yara /tmp/base58-candidates.yar sample.txt
```

The candidate rule defaults to 26 through 35 characters. It accepts checksum-invalid
addresses and ordinary alphanumeric text with that alphabet and length. Plain
Base58 has no checksum, so alphabet membership alone cannot establish that text
was intentionally encoded.

## Validation and sources

```sh
PYTHONPATH=src python3 -m pytest -q -m base58
```

Tests cover public Base58 vectors, strict malformed-input rejection, leading
zeroes, all alphabet values, decoded integer words through 128-character inputs,
complete SHA-256 digests against Python's `hashlib` for multiple single-block
message lengths, and end-to-end generated checksums. End-to-end cases include
the genesis address, a mutation at every character position, deterministic
generated addresses, candidate slots 1 and 2, boundaries, and explicit unsupported
formats and later-candidate behavior.

Public algorithm sources:

- [Bitcoin Core Base58 and Base58Check](https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp)
- [Bitcoin Core Base58 test vectors](https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json)
- [NIST FIPS 180-4: SHA-256](https://doi.org/10.6028/NIST.FIPS.180-4)
- [YARA hash module API](https://yara.readthedocs.io/en/stable/modules/hash.html)
