# RIAK Differential Fuzzing: Rust vs Python Reference

Date: 2026-09-26

Tools: `examples/v3_fuzz_generate.rs`, `simulator/fuzz_diff_v3.py`

## Why this exists

The Rust implementation and the Python reference in `simulator/riak_v3.py` share
no code. That independence is the entire point: a divergence means at least one
of them is wrong, and since they were written separately from the same
specification, agreement across a large body of cases is real evidence that both
are correct.

Before this harness, the two implementations had been compared on 128
generated cases stored as fixed vectors. That is enough to catch a transcription
mistake and not enough to catch an edge case. This harness replaces fixed vectors
with generated cases whose count is a parameter.

## What is compared

For each generated case the checker verifies three things:

1. the ciphertext and tag produced by the Python reference match the Rust output
   byte for byte;
2. decrypting the Rust output with the Python reference returns the original
   plaintext;
3. parsing succeeded, so an empty aad or an empty plaintext is handled.

Lengths are drawn from a fixed ladder of `[0, 1, 15, 16, 17, 31, 32, 33, 63, 64]`
plus a multiple of 16, rather than from a uniform random range. A uniform range
almost never produces 0 or 1 mod 16, so the partial-block paths would go
untested. Cases are grouped so several messages share one key, which also
exercises repeated key-schedule use.

Generation is driven by a seed, so any failing case is reproducible.

## Results

| seed | cases | ciphertext/tag | round-trip |
|---|---|---|---|
| 1 | 60000 | 60000 match, 0 mismatch | 60000 ok |
| 2 | 60000 | 60000 match, 0 mismatch | 60000 ok |
| 3 | 60000 | 60000 match, 0 mismatch | 60000 ok |
| 4 | 60000 | 60000 match, 0 mismatch | 60000 ok |
| 5 | 60000 | 60000 match, 0 mismatch | 60000 ok |
| **total** | **300000** | **0 mismatches** | **0 failures** |

No divergence was found. CI runs a smaller 3-seed x 20000-case set on every
change; the 300000-case run above was the one-off deep pass.

## What this does and does not prove

**Proves, for the tested input family:** that the two implementations agree on
ciphertext, tag, and decryption, including at partial-block lengths, empty
inputs, and repeated keys. A disagreement here would have been a real defect.

**Does not prove:**

- anything about the security of either implementation;
- that untested input shapes behave identically, since the length ladder and
  byte distribution are still a choice, not a proof of coverage;
- anything about the block cipher's raw behaviour, since the wrapper is what is
  exercised here.

The generator and checker are in CI, so future changes to either implementation
are re-checked automatically and a regression fails the build rather than being
found later.

## Reproducing

```bash
# one-off deep pass
cargo run --release --example v3_fuzz_generate -- 60000 1 /tmp/cases-1.txt
python3 simulator/fuzz_diff_v3.py /tmp/cases-1.txt

# add --verbose for progress on long runs
python3 simulator/fuzz_diff_v3.py /tmp/cases-1.txt --verbose
```
