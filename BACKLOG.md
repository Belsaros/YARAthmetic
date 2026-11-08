# YARAthmetic Backlog

> **YARA is a pattern-matching engine.**
>
> This is a list of increasingly elaborate ways to take that statement personally.

YARAthmetic generates self-contained YARA rules for calculations that sensible people would perform in a programming language. The project began with checksum validation, wandered into SHA-256, and has now attracted the sort of feature requests normally preceded by "hear me out."

This file is a **wishlist, not a roadmap**. Items are ordered roughly by increasing computational absurdity, compiler distress, and probability that someone will ask whether the maintainer is okay. Actual priorities depend on usefulness, feasibility, and how funny the benchmark results are.

## Level 0 — Legitimate Software Engineering

*We are a normal security project. Please disregard the smoke.*

- [ ] **Broaden checksum coverage.** Investigate CRC variants, Adler-32, ISBN-10/13, IBAN, VIN check digits, and other formats where mathematical validation reduces false positives.
- [ ] **Make generated rules smaller and faster.** Common-subexpression elimination, smarter circuit layouts, candidate selection, and benchmarks for source size, compilation time, memory, and scan throughput.
- [ ] **Improve forensic ergonomics.** Clear documentation of what a match proves, what it does not prove, and how to recover candidate offsets and bytes for follow-up analysis.
- [ ] **Expand compatibility and regression testing.** Keep testing against actual YARA releases. A generated rule that compiles only on the developer's machine is performance art, not a release.
- [ ] **Build a reproducible benchmark corpus.** Include synthetic positives, adversarial negatives, boundary cases, and carefully labeled false-positive experiments. No live secrets, thank you.

## Level 1 — Cryptographic Artifact Hunting

*Still defensible in a security conference talk. Probably.*

- [ ] **Validate uncompressed secp256k1 public keys.** Locate `0x04 || X || Y` candidates and check `Y² ≡ X³ + 7 (mod p)` using generated 256-bit arithmetic. Start with one selected candidate per scan. A valid point is not evidence of malware; it is evidence that we found a point.
- [ ] **Add other elliptic-curve formats.** Explore compressed secp256k1, Ed25519, and other encodings. Document when mathematical validity is a weak discriminator: roughly half of candidate compressed secp256k1 X coordinates correspond to curve points.
- [ ] **Recognize structured RSA keys.** Detect DER/PEM, PKCS#1/#8, SubjectPublicKeyInfo, and common key blobs. Validate lengths, integer encodings, and other structural invariants before attempting crimes against number theory.
- [ ] **Validate RSA private-key relationships.** For sufficiently well-structured candidates, check relationships such as `n = p × q` and CRT consistency. This may help identify exposed private keys in firmware, binaries, or memory dumps. It will also help identify the limits of the compiler's patience.
- [ ] **Explore other structured key material.** JWK, OpenSSH, and platform-specific key containers; prioritize recognizable layouts over magical claims about detecting arbitrary AES keys. Random bytes are very good at pretending to be random bytes.
- [ ] **Add Ethereum EIP-55 checksum validation.** Investigate Keccak-256 in generated YARA. Another checksum, another opportunity to explain why a cryptographic hash function has been converted into a pattern-matching condition.

## Level 2 — Cryptography, But Make It Everyone's Problem

*The threat model now includes the generated rule itself.*

- [ ] **Implement generic multi-precision arithmetic circuits.** Addition, subtraction, multiplication, comparison, and modular reduction across 256-bit and larger integers. Prefer reusable generator primitives, because copy-pasting a million Boolean expressions is not a maintainability strategy.
- [ ] **Implement elliptic-curve point addition and doubling.** Begin with known test vectors. Do not begin with a production ECDSA verifier just because the whiteboard has room.
- [ ] **Attempt secp256k1 scalar multiplication.** Benchmark compile time, rule size, and scan time. Record the exact point at which the machine begins negotiating.
- [ ] **Attempt ECDSA signature verification.** Verify a known digest/signature/public-key tuple entirely in stock YARA. Useful in narrow artifact-authentication scenarios; likely a terrible substitute for a cryptographic library.
- [ ] **Attempt RSA signature verification.** Public exponent 65537 means a manageable exponentiation schedule, provided we ignore the small matter of 2048-bit modular arithmetic.
- [ ] **Investigate cryptographic fingerprinting and correlation workflows.** Let YARA find and validate candidate objects; let a separate tool extract, hash, and correlate them. Even this project is allowed to delegate occasionally.

## Level 3 — Computational Misconduct

*"YARA isn't a general-purpose language" has become a challenge rather than guidance.*

- [ ] **Conway's Game of Life.** Feed a board state into a scan and have generated rules determine the next generation. The external harness maintains state. YARA is not secretly hiding a mutable framebuffer under the floorboards.
- [ ] **Build a tiny arithmetic logic unit.** Accept encoded operands and an opcode; emit results via rule matches or another explicitly documented output channel. Congratulations: we have invented a very slow calculator.
- [ ] **Emulate a tiny virtual machine.** Start with a bounded instruction set and one instruction per scan. Require a test ROM and a clear division between YARA computation and the external host that stores state.
- [ ] **Run CHIP-8.** 4 KB of address space, a 64×32 display, and a respectable history of being ported to things that should not run games. If the host does the emulation and YARA only checks a checksum, it does **not** count.
- [ ] **Generate a maze raycaster.** Fixed-point arithmetic, lookup tables, bounded ray traversal, and externally rendered frames. Aim for a recognizable corridor before promising an engine.

## Level 4 — CAN IT PLAY DOOM?

*There is no longer a product manager. There is only momentum.*

- [ ] **Render one Doom-like frame using YARA-computed geometry.** The host may display pixels; YARA must do meaningful rendering computation. A screenshot matched by a YARA rule is not a game engine, no matter how enthusiastically we name the file `doom.yar`.
- [ ] **Move through a Doom-like level.** Accept player input and serialized state, calculate the next state in YARA, and return enough information for the host to display it. Measure frames per second, or frames per fiscal quarter, whichever is more flattering.
- [ ] **Run an actual Doom gameplay subsystem.** Pick a bounded piece of real game logic and reproduce it with generated YARA conditions. Start small. The phrase "full source port" is hereby classified as an incident indicator.
- [ ] **Attempt actual Doom.** Real assets, real game rules, and enough YARA-executed computation that calling it "Doom in YARA" isn't fraud. An external input/output/state harness is permitted and must be disclosed. Performance expectations: emotionally prepare for a slideshow.
- [ ] **Publish the benchmark.** Report generated rule size, compilation time, peak memory, scan latency, and how many times the test machine's fans audibly objected. No benchmark is complete without a confession.

## Level 5 — The Compiler Has Requested Legal Representation

*These are jokes until somebody opens a pull request.*

- [ ] **Write a YARA interpreter in generated YARA.** Start with a toy subset. Continue until someone points out that we have recreated the thing we're already using, only worse.
- [ ] **Implement a tiny compiler in YARA.** Parse a deliberately microscopic expression language and report its output through rule matches. A self-hosting compiler is not a milestone; it is a cry for help.
- [ ] **Make YARA play Doom inside a CHIP-8 emulator inside YARA.** The external harness is now responsible for explaining to the operating system what happened.
- [ ] **Generate a rule that determines whether generating the rule was a good idea.** Expected result: `false`. Treat any other result as a critical correctness bug.
- [ ] **Get YARA to file its own GitHub issue.** Title: `Please stop.` Priority: `blocker`. Assigned to: everyone who encouraged this.

---

## Ground Rules (We Still Have Those)

1. **Stock YARA at scan time.** Generation and testing may use Python or other tools; generated rules should not quietly require an external crypto library to do the actual validation.
2. **Be explicit about the host.** YARA scans are not persistent game loops. If a demo needs an external process for state, input, output, or repeated scans, say so prominently.
3. **Correctness before spectacle.** Independent test vectors, negative tests, and compatibility results come before triumphant screenshots.
4. **Measure the pain.** Rule size, compilation time, memory, and throughput are first-class results, including when the result is "no."
5. **Don't confuse validity with maliciousness.** A valid public key is a valid public key. Context and attribution remain somebody's job.
6. **Never scan or publish real private keys as demo fixtures.** Synthetic test material exists for a reason.
7. **Failure is publishable.** A documented compiler limit is useful research. A compiler crash is a bug report. A compiler that plays Doom is an existential event.

## Definition of Done

A feature is done when it has tests, documentation, reproducible measurements, clearly stated limitations, and a result that can be distinguished from a Python script doing all the work while YARA watches.

A feature is **spiritually done** when the YARA maintainers see it and respond with some variation of:

> Why?

**Project motto:** *The documentation says it's a pattern-matching engine. We disagree.*
