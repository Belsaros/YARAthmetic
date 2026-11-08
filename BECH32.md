# Compact Bech32 and Bech32m rules

The default generator now emits one shared checksum calculation instead of
separate expressions for every combination of candidate length and HRP length.
The resulting rule still considers every regex occurrence and all 3,486 shapes
with total length 8 through 90, HRP length at least one, and at least six data
characters. Both Bech32 and Bech32m constants are accepted.

## Results

Measurements below use YARA 4.5.2 on the same development machine and the same
seven-file, 131,358-byte corpus with seed 12345. Decimal units are used.

| Measurement | Original full unrolling | Compact |
| --- | ---: | ---: |
| Source bytes | 193,143,862 | 253,998 |
| Compiled bytes | 138,259,357 | 210,038 |
| Compilation, one run | 9.20 s | 0.02 s |
| Full corpus scan | 12.25 s | 10.58 s |
| Peak scan RSS | 218,320 KiB | 7,852 KiB |
| 100 KiB candidate storm, separate scan | 10.38 s | 10.25 s |
| Incorrect file classifications | 0 | 0 |

The main improvements are roughly 760-fold smaller source, 658-fold smaller
compiled output, much cheaper compilation and loading, and about 28-fold lower
scan memory. The candidate storm's arithmetic cost remains similar. These are
single-run timings, not evidence of a substantial checksum-throughput gain;
values reported as 0.00 seconds in the JSON are below the timer's precision.

Raw measurements are in
[original](benchmarks/bech32-unrolled-yara452.json) and
[compact](benchmarks/bech32-compact-yara452.json).
The older `bech32-full-shape-baseline-v2.json` was recorded on different hardware
and a different YARA version, so it is not used for timing comparisons here.

## Generate and use

The committed [generated rule](generated/bech32.yar) needs only YARA at scan time.
No modules, external variables, callbacks, or Python runtime are required.

```sh
PYTHONPATH=src python3 -m yarithmetic
yara generated/bech32.yar sample.txt
yarac generated/bech32.yar /tmp/bech32.yarc
yara -C /tmp/bech32.yarc sample.txt
```

`generate_bech32_rule()` selects the compact implementation. Passing an explicit
`shapes=[(length, hrp_length), ...]` retains the previous unrolled implementation,
which is smaller for a few known shapes. The original full-coverage generator
remains available as `generate_bech32_rule_unrolled()` for comparisons. The
compact generator can also apply explicit shape restrictions when called directly.

YARA 4.5.2 was tested here. The new rule has at most four nested loops, including
singleton loops used to bind intermediate integer values. Other versions still
need their own compatibility runs. The broad candidate regex continues to
produce YARA's slow-string warning.

## How the shared calculation works

Let `T(s) = polymod_step(s, 0)`. This is a linear, invertible transformation of
the 30-bit checksum state. Let `n` be the total candidate length, `h` the HRP
length, and `c` the appropriate Bech32 or Bech32m final checksum constant.

The expanded checksum input contains `n + h` symbols. Appending `90 - n` zero
symbols changes a valid checksum from `c` into `T**(90 - n)(c)`.
After this padding, the calculation can be factored as

```text
T**h(H) XOR R == T**(90 - n)(c)
```

For original character position `p`:

- `H` starts with `T**90(1)` and includes HRP high-bit contributions at fixed
  distance `89 - p`.
- `R` includes HRP low-bit contributions at fixed distance `88 - p`, and data
  contributions at fixed distance `89 - p`.
- Arithmetic flags activate HRP terms when `p < h`, data terms when
  `h < p < n`, and suppress every other term.

The generator unrolls these fixed-distance contributions once. It then applies
`T**h` in two stages, splitting `h` into low and high groups of four bits.
Small transition tables store pairs of 30-bit coefficients in positive 60-bit
integer constants; runtime arithmetic selects a coefficient. This replaces the
eight nested loops explored in the earlier distance-transition experiment.

`H` and `R` fit together in one 60-bit binding. Candidate iteration, HRP iteration,
that binding, and the first transition binding use four nested loops total.
Both final checksum constants are compared after the second transition.

Inactive character positions still read a byte *inside* the candidate using a
wrapped index. This matters at EOF: an out-of-file `uint8` is undefined in YARA,
and multiplying an undefined value by zero does not neutralize it. The separator
is explicitly required to be the last `1` in the candidate.

Candidate extraction retains the original printable-ASCII regex and left
boundary policy. Thus these are detections of extracted candidates, rather than
a whole-file validator. Uninterrupted printable text before an identifier can
prevent its extraction; boundary-policy changes are separate from this checksum
optimization.

## Validation

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_bech32_compact.py
```

The exhaustive regression creates 13,944 files: a valid value for each of the
3,486 shapes in each encoding, plus one checksum mutation for every value.
It varies HRP characters and case and includes maximum-length and empty-payload
values. All observed results agree with the Python reference validator.
Additional tests cover public vectors, all 128 packed-lookup indices, shape
restrictions, late valid candidates after 400 invalid ones, mixed case, boundaries,
EOF, and reproducibility of the committed rule.

The pre-existing experimental tests for eight nested distance-transition loops
and nesting depths above four still fail on YARA 4.5.2 (17 cases). They were
retained; the production generator does not use that implementation.

To reproduce a compact benchmark workspace with the existing harness:

```sh
PYTHONPATH=src python3 -c 'from yarithmetic.benchmark.runner import prepare_workspace; prepare_workspace("/tmp/bech32-benchmark", seed=12345)'
PYTHONPATH=src python3 tools/benchmark-bech32 /tmp/bech32-benchmark --output /tmp/bech32-metrics.json
```

Algorithm specifications:
[BIP 173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) and
[BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).

## Output version

The main generator accepts `--output_version`, for example:

```sh
PYTHONPATH=src python3 -m yarithmetic --kind bech32 --output_version 3.6.3 --output-dir /tmp/bech32-3.6.3
```

The Python APIs accept the matching `output_version="3.6.3"` keyword. Bech32
requires YARA 3.5 or later because it uses match lengths. See
[compatibility](COMPATIBILITY.md) for the 3.6 regex workaround and Docker tests.
