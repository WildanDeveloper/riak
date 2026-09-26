# RIAK DDT/LAT probe

A standalone research crate that measures the RIAK v0.3 round function with
**exact** combinatorics instead of sampling.

It is deliberately **not** part of the `riak` library. It depends on `riak`
only to cross-check that its own specification-derived copy of the round
function, key schedule, and outer network match the shipped implementation
before it measures anything. If the probe and the library ever disagree, the
probe fails instead of reporting numbers for the wrong function.

## What it computes

- **Exact DDT** of the keyless round bijection truncated to `w < 32` bits.
  Full-width DDT is out of reach: one row needs `2^32` counters and the table
  has `2^64` entries.
- **Exact LAT** of the same map, via fast Walsh-Hadamard transform, excluding
  the trivial `a = 0` and `b = 0` masks.
- **Exact minimum trail activity** through the v0.3 four-branch outer network,
  as a dynamic program over all 16 difference-activity patterns. The model
  grants the attacker the most favourable nonzero F output for free, so the
  result is a lower bound, which is the safe direction.
- **Exact truncated-differential screen** on a reduced-width block, enumerating
  all `2^(4W)` reduced inputs for each nonzero input-difference pattern.
- **Key-independence verification**: the DDT and the absolute LAT are shown
  numerically to be independent of the round key, because
  `F(x,k,c) = H((x ^ k) + c)` and `x -> x ^ k` preserves every XOR difference.

## Running

```bash
# fast regression run (used by scripts/ci.sh)
cargo run --release -- --width 12 --key-independence \
  --assert-diff-log2 4 --assert-zero-log2 1 --assert-corr-log2 2

# self-tests: Parseval, DDT row sums, zero column, key independence, activity
cargo test --release

# deeper measurement
cargo run --release -- --width 14 --cross-check 200000 --cross-check-blocks 500

# reduced-block truncated screen (about 30 s at width 5)
cargo run --release -- --skip-ddt --skip-lat --reduced-block 5

cargo run --release -- --help
```

## Interpreting the output

The tool prints, for each probed map, the measured maximum against a
**random-permutation reference**:

- DDT reference `4 w ln 2`, a Poisson extreme-value estimate with mean `1/2`
  per entry.
- LAT reference `sqrt(2^w * ln(2^(2w)))`, a Gaussian extreme-value estimate.

These are reference points for "is this in the range a random permutation would
also produce". They are **not** security thresholds, and a ratio above 1 is not
a break.

Reduced-width results do not transfer upward. A large truncated probability is
a real red flag; a small one is not evidence of safety. The recorded
measurements and their caveats are in `docs/riak_v3_ddt_lat.md`.

## Exit status

| code | meaning |
|---|---|
| 0 | completed and every requested assertion held |
| 1 | an assertion failed, or a cross-check disagreed with the library |
| 2 | invalid arguments |
