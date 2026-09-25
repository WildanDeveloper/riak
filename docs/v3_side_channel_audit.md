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
- `Drop` performs best-effort zeroization with `black_box`; the v0.3 key
  schedule and byte-key constructors also clear their local word arrays after
  expansion. This is not a formal memory-safety guarantee against
  compiler/platform copies.

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

1. Run a real leakage-detection/statistical timing tool on fixed and random
   classes with multiple compiler targets and optimization levels.
2. Inspect generated assembly for every supported target, including ARM and
   wasm if claimed.
3. Use a memory/key-lifetime audit tool and define a zeroization contract.
4. Test long-message mode/tag behavior separately from block encryption; public
   length-dependent loop timing is expected and must be accounted for.
5. Re-run the audit after any compiler, target, or wrapper change.
