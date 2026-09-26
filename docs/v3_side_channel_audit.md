# RIAK v0.3 Side-Channel Audit Record

Date: 2026-09-25

This is an implementation audit, not a constant-time proof. The required
statistical tools (`dudect`, `ctgrind`, `valgrind`, `perf`) and the optional
`rustfmt`/`clippy` components were not available in the development
environment.

## Source review

Reviewed: `src/v3.rs` and the v0.3 calls in `src/main.rs`.

- `#![forbid(unsafe_code)]` is enabled.
- `RiakV3::encrypt_block`, `decrypt_block`, and the four-way interleaved path
  use fixed round/sub-update loops and fixed-size arrays.
- F uses only XOR, wrapping addition, odd multiplication, shifts, and rotates;
  it has no data-dependent branch, memory index, or table lookup.
- Round-key and constant indices are derived only from public fixed loop
  counters. The current sixteen-word key-schedule sweep and sixteen-step
  nonlinear round-key extraction use fixed `0..16` loops and public index
  arithmetic.
- The wrapper's `decrypt` flag selects encryption versus decryption and is an
  API mode, not secret data. Branches driven by message length, nonce parsing,
  allocation failure, and tag result occur outside the block-cipher core.
- Tag comparison iterates over a fixed 16-byte array, accumulates XOR
  differences, and only branches after the complete comparison.
- `Drop` performs best-effort zeroization with `black_box` for v0.1, v0.2,
  and v0.3; the key schedule and byte-key constructors also clear their local
  word arrays after expansion. This is not a formal memory-safety guarantee
  against compiler/platform copies.

The source review found no intentional secret-dependent control flow in the
v0.3 core. This does not cover compiler transformations, microarchitecture,
speculative execution, allocator behavior, or key material copies.

## Release assembly inspection

Built with:

```text
cargo build --release --bin riak
objdump -d target/release/riak
```

The `riak::v3::RiakV3::encrypt_block` symbol was inspected after the schedule
revision. Its arithmetic body contains `imul`, add, XOR, shift, and rotate
instructions. The only loop branch in the core compares a public round counter
against the fixed round count (`24`); round-key loads use that public counter.
The `from_words_with_domain` symbol showed fixed-counter branches for the
24-round sweep, sixteen-word state update, and sixteen-step extraction; no
branch based on a key, plaintext word, or intermediate F output was visible in
these symbols. The explicitly unrolled `encrypt_block_x4` symbol was also
inspected in the benchmark binary and showed the same fixed-counter pattern.

The `RiakV3Cipher::open` symbol was also inspected. Its early length check is
public-length validation. The tag comparison was compiled to fixed-width
packed operations followed by a final result branch; no early exit inside the
16-byte comparison was visible. The mode loop has length/chunk-control
branches, which depend on public message length rather than secret values.

This is a single compiler/architecture observation (`x86_64` development host),
not a portable constant-time guarantee. A compiler upgrade or different target
requires a new inspection.

## Statistical first-order leakage screen

`dudect` and `ctgrind` are not installed in this environment, but the
ingredients for a first-order test are available: the CPU can be pinned with
`taskset`, the process can be raised with `chrt`, and the hardware cycle counter
is readable from Rust. `examples/v3_leakage.rs` implements a dudect-style
first-order test directly, including a **negative control**.

Method: measure `encrypt_block` for a fixed-plaintext class and a random-plaintext
class, randomise the order within each round to cancel drift, and compute Welch's
`t`. The negative control compares two classes that are **both constant** (two
different fixed blocks). Since the cipher does identical work for both control
classes, a significant control `t` would mean the measurement setup is biased and
the main result cannot be attributed to the cipher.

Command:

```text
taskset -c 0 chrt -f 5 cargo run --release --example v3_leakage -- 1500000
```

Five consecutive runs, pinned and at real-time priority:

| run | fixed-vs-random t | negative-control t |
|---|---|---|
| 1 | -4.95 | -2.60 |
| 2 | -3.45 | -1.50 |
| 3 | -5.07 | -0.01 |
| 4 | -4.84 | -1.02 |
| 5 | -5.40 | -1.49 |

**Finding: a small but consistent first-order timing signal.** The
fixed-vs-random `t` is negative on every run (mean about -4.75, mean difference
about -6 cycles or -0.3%), while the negative control stays close to zero on
every run. The consistent sign, combined with a clean control, means this is not
random noise and not a harness artefact.

The source is not identified. `encrypt_block` and `encrypt_round` contain no
data-dependent branch, no table lookup, and no variable-latency instruction, so
the arithmetic is constant by inspection. The residual bias is small and its
origin is unknown: it may be a microarchitectural data dependency (for example
a multiplier or a shift whose latency depends on operand values), a
measurement-environment effect that the control does not capture, or an artefact
of the sample pairing. **This is an open item, not a cleared one.** It must be
resolved before any constant-time claim is made about v0.3.

This screen still does not cover second-order leakage, the cache, port
contention, speculative execution, power analysis, other hardware, other
compilers, or the wrapper mode and tag paths.

## Automated assembly screen

`scripts/asm_audit.sh` turns the manual inspection above into a repeatable
check that runs in `scripts/ci.sh` and exits non-zero on a finding.

It resolves each v0.3 symbol through `nm` (because `objdump` prints Rust
v0-mangled names), extracts the function body by address range, and reports:

- **Integer division.** Any `div`/`idiv` in the core is a finding, because
  division is variable-time on most hardware.
- **Computed memory addresses.** Reported as *leads*, not findings. A
  `(base,index,scale)` operand can be a linear buffer scan with a public loop
  index, which is harmless, or a secret-indexed table lookup, which is a cache
  leak. Telling those apart requires data flow analysis that the script does
  not attempt.
- **Conditional branches.** Counted and listed so a reviewer can confirm each
  one is driven by a public length or round counter.

Result on the current build: no integer division, all six core symbols
(`encrypt_block`, `from_words_with_domain`, `seal`, `open`, `racik`,
`auth_tag`) present and screened, 77 conditional branches reviewed by hand as
loop and length counters.

A pass means only that no division and no obvious secret-dependent control flow
were found in this build. It is explicitly **not** a constant-time guarantee,
and it does not cover the microarchitecture, speculative execution, allocator
behaviour, or any other toolchain.

## Timing smoke test

Command:

```text
cargo run --release --example v3_timing
```

Observed fixed/random timings on the development host varied from roughly
`0.6–1.8 µs/block` across runs, with differences both near zero and tens of
nanoseconds. The large run-to-run variation, ordering, frequency scaling,
allocator state, and other noise make these measurements non-conclusive. The
tool is intentionally labeled a rough smoke test and is not evidence of
leakage or of constant-time behavior.

## Open work

1. **Resolve the first-order timing signal** measured above. The negative
   control is clean while the fixed-vs-random difference is consistent at about
   -0.3%, so the setup is sound and the source is unexplained. Determine whether
   it is a real data dependency in the core or a measurement artefact before
   making any constant-time claim.
2. Extend the statistical screen to the wrapper mode and tag paths, which are
   not covered, and to second-order leakage.
3. Run the screen on multiple compiler versions, optimization levels, and
   targets. `dudect` and `ctgrind` are still unavailable here, so the current
   test is a hand-written first-order substitute.
2. Inspect generated assembly for every supported target, including ARM and
   wasm if claimed. `scripts/asm_audit.sh` currently covers the `x86_64` host
   build only.
3. Replace the computed-address *leads* with real data flow analysis, or a
   human review recorded per symbol, so the screen can distinguish a public loop
   index from a secret-indexed table.
4. Use a memory/key-lifetime audit tool and define a zeroization contract.
5. Test long-message mode/tag behavior separately from block encryption; public
   length-dependent loop timing is expected and must be accounted for.
6. Re-run the audit after any compiler, target, or wrapper change.
