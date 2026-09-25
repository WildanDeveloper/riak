# RIAK v0.2 Initial Analysis Record (Rejected for Production)

Date: 2026-09-25

**Status: rejected for production, retained for reproducibility.** v0.2 has
not passed the complete security gates. An earlier draft incorrectly claimed
an unconditional outer invariant; direct implementation checking falsified that
claim because the output-word indices were misread. No such invariant is used
as evidence here. The records below are not a security clearance.

## Structural checks

- `mix_a`, `mix_b`, and `mix_c` each have GF(2) rank 32 over the 32 basis
  vectors.
- `MUL_A`, `MUL_B`, and `MUL_C` are odd, so each modular multiplication is
  bijective.
- The resulting candidate F is therefore a permutation.
- The v0.1 masks `0x33333333`, `0x55555555`, and `0x99999999` do not produce
  a deterministic full-24-round relation in the candidate sample.

## Differential screen

Command:

```text
cargo run --release --example v2_ddt
```

Sample results on the development host:

- 512 random input differences × 2^16 samples: top observed count 2.
- All 1-bit and 2-bit input differences × 2^18 samples: top observed count 3.

These are sampling results only. The maximum over many differences and bins
still requires a multiple-testing correction and a larger search.

## Linear screen

Commands:

```text
cargo run --release --example v2_probe
cargo run --release --example v2_linear
```

The structured single-bit/old-kernel mask screen found a maximum sampled bias
of approximately `0.005859` at 2^16 samples per pair. This is compatible with
sampling noise and is not a bound on linear trails or linear hulls.

Full-block screens:

- `v2_differential`: 2^20 pairs/cell for four representative differences;
  every tested 4/6/8/12/24-round cell had top count 1.
- `v2_full_linear`: 35 structured masks, 2^16 samples/pair; maximum sampled
  bias was approximately 0.0072 at reduced rounds and 0.0055 at 24 rounds.

- `v2_trail_search`: 497 top-bit/low-bit candidates measured at 2^16 samples;
  the top 16 were searched with 1,000,000-node budget. No feasible trail was
  found in that measured family.
- `v2_related`: 4,096 one-bit related-key cases × 4 blocks; average output
  Hamming distance 64.018, minimum 41, zero-difference blocks 0.

These remain sample-based screens and do not replace a serious related-key
analysis.

## Wrapper checks

- Rust/Python block vectors: 12/12 match.
- Rust/Python custom wrapper vectors: 3/3 match.
- 128 deterministic randomized seal/open cases pass.
- CLI v0.2 roundtrip, key-file input, tag tampering, and nonce tampering pass.
- Tag verification occurs before plaintext is returned.

## Open gates

- Structured LAT and linear-hull search.
- Multi-round differential trail search with per-difference bounds.
- Related-key and domain-separation analysis.
- Side-channel/compiler measurement.
- Mode-specific nonce-reuse and error-propagation analysis.
- Independent external cryptanalysis and review.

Because the remaining gates are incomplete, v0.2 and `RIAK2C` are rejected
for new data. They remain available only as legacy research artifacts; the
disproved outer-invariant claim is not a reason for rejection.
