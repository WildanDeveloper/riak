# RIAK v0.3 Reduced-Width DDT/LAT and Trail-Activity Screen

Date: 2026-09-26

Tool: `analysis/ddt-probe` (`riak-ddt-probe`)

**This document records a bounded screen. It is not a security proof and it is
not a cryptanalysis of the full 128-bit block.** Every number below is an
exact computation on a reduced-width model, and reduced-width results do not
transfer to the full width. The honest summary of this document is: *no
weakness found in the tested reduced families; the full-width families remain
unanalyzed.*

## Why reduced width carries any information

Every step of the round function is compatible with projection onto the low
`w` bits: XOR, modular addition, odd multiplication, and shift/rotate all
satisfy `low_w(F(x)) = F_w(low_w(x))`. The truncated output-difference
distribution is therefore the marginalisation of the full-width distribution.

Consequences, and they pull in opposite directions:

- A **large** truncated differential or linear probability is a rigorous red
  flag, because the full width cannot be better than its marginal.
- A **small** truncated probability proves **nothing** about the full width.
  The full-width table can still contain a much stronger entry.

Full-width enumeration is out of reach on any machine. One DDT row needs
`2^32` counters, and the table has `2^64` entries. This is the same wall that
blocks any full LAT as well.

## Key independence of the DDT and the absolute LAT

The round function factors as

```text
F(x, k, c) = H((x ^ k) + c)
```

where `H` is independent of the round key. For a fixed `k`, the substitution
`x -> x ^ k` is a bijection that leaves every XOR difference unchanged, so:

- `DDT[dx][dy]` is **identical for every round key**. The difference
  distribution table does not depend on the key at all.
- For the LAT, substituting `u = x ^ k` gives
  `<a, x ^ H(u)> = <a, u ^ k> ^ <a, H(u)>`, so the correlation picks up the
  factor `(-1)^<a, k>`. The **absolute** correlation is key-independent and
  only the sign changes.

This is verified numerically rather than assumed:

```text
k=0x00000000 c=0x00000002: DDT identical true, |LAT| identical true
k=0xFFFFFFFF c=0x13579BDF: DDT identical true, |LAT| identical true
k=0xA5A55A5A c=0x2468ACE0: DDT identical true, |LAT| identical true
k=0x5A5AA5A5 c=0xFEDCBA98: DDT identical true, |LAT| identical true
key independence: confirmed numerically
```

This is the first genuinely useful structural result of the exercise. It means
one reduced-width measurement stands in for **all** round keys, so the
previously open "per-key DDT" item does not require a separate key sweep for
this construction. It does not say anything about related-key behaviour of the
key schedule, which is a different question and is still open.

## The zero column of the DDT is exactly empty

Measured for every probed map at every tested width:

```text
DDT: zero column (absorption) max 0/16384, mean 0, rows above 1: 0
DDT: input-difference rows containing a probability-1 pair: 0 of 16383
```

This is a required structural property, not an accident of the constants. `F`
is a permutation, so `F(x) != F(x ^ dx)` for every nonzero `dx`; an active F
evaluation can never absorb a difference. The probe asserts it as a regression
test, because losing it would mean the round function stopped being a
bijection and the key schedule and mode would both be broken.

The practical consequence is that the activity pattern of a block difference
through the outer network is deterministic in structure, and a nonzero
difference can never quietly collapse to zero.

## Exact DDT/LAT of the keyless round bijection

Command:

```text
cargo run --release --manifest-path analysis/ddt-probe/Cargo.toml -- \
  --width 14 --cross-check 200000 --cross-check-blocks 500
```

The probe re-derives the round function, key schedule, and outer network from
the specification and cross-checks all three against the shipped
implementation before measuring anything:

```text
cross-check: OK                      (200000 random round-function cases)
block cross-check: OK                (500 random whole-block cases)
```

Reference columns: for a uniformly random permutation of `2^w` elements, the
expected maximum DDT count is approximately `4 w ln 2` (a Poisson
extreme-value estimate with mean `1/2` per entry), and the expected maximum
`|W|` is approximately `sqrt(2^w * ln(2^(2w)))` (a Gaussian extreme-value
estimate). Both are theoretical references, not guarantees.

| map | max DDT count | ratio vs random | max \|W\| | ratio vs random |
|---|---|---|---|---|
| core `k=0, c=0` | 76 / 16384 = 2^-7.75 | 2.0x | 2320 = 2^-2.82 | 5.6x |
| slot0 `c=0x00000002` | 66 = 2^-7.96 | 1.7x | 1404 = 2^-3.55 | 3.4x |
| slot3 `c=0xFEDCBA9A` | 56 = 2^-8.19 | 1.4x | 1404 = 2^-3.55 | 3.4x |

Reference values at width 14: DDT about 39, LAT about 413.

**Reading this honestly.** The differential maxima sit within a small factor of
a random permutation, which is unremarkable. The **linear** maxima are roughly
3.4x to 5.6x above the random reference, and the best masks are low weight
(`a=0x9` for the core map). That is the signature of an ARX construction at
truncated width, where carry and rotate boundaries dominate, and it is the
reason ARX designs are normally argued with trail bounds rather than table
maxima. It is **not** evidence of a linear weakness at 32 bits, and it is
**not** evidence of safety either. It is a signal that the full-width linear
families deserve a proper trail and hull search, which is exactly the item
still marked open.

The individual layers behave exactly as the design intends, and the probe
confirms it rather than assuming it:

- `mix_a`, `mix_b`, `mix_c` are pure GF(2)-linear maps: every one of the
  16383 nonzero input differences has a single output difference with
  probability 1, and `|W| = 2^w` for the matched mask pairs. Their security
  contribution is diffusion, not nonlinearity.
- `mul_a` and `add_a` each have one deterministic high-bit transition
  (`dx=0x2000 -> dy=0x2000` at probability 1), which is the ordinary behaviour
  of multiplication and addition modulo `2^w` at the top bit and is the reason
  the composite, not the individual layers, is what must be measured.

## Exact minimum trail activity through the outer network

The probe computes, by dynamic program over all 16 difference-activity
patterns, the minimum number of active F evaluations in any 24-round trail
that starts and ends with a nonzero block difference.

The model is deliberately optimistic: it grants the attacker, for free, the
nonzero F output value that cancels the most word activity. The result is
therefore a **lower bound** on the true activity, which is the safe direction.

```text
start weight 1 -> 51 active F calls
start weight 2 -> 48 active F calls
start weight 3 -> 49 active F calls
start weight 4 -> 50 active F calls
smallest minimum across all nonzero starts: 48
```

Out of 96 available F calls in 24 rounds, no trail can use fewer than 48. This
is a genuine structural result: the v0.3 outer network forces at least two
active F evaluations per round on average, and there is no cheap
single-active-round path.

It is still only a **per-trail** screen. It does not bound differential-hull
accumulation over many trails, and it does not bound the full-width
per-transition probabilities.

## Exact truncated screen on a reduced block

`--reduced-block W` runs all `2^(4W)` reduced inputs of the full 24-round
cipher for each of the 15 nonzero input-difference patterns and reports the
distribution of the output-difference Hamming weight.

At `--reduced-block 5`, every one of the 15 patterns gave `P[weight 0] = 0`
exactly, and the weight distribution stayed close to the random-permutation
expectation `C(4,k)/16`:

```text
pattern 0x1 -> 1:0.00012  2:0.00542  3:0.11291  4:0.88155
pattern 0xF -> 1:0.00012  2:0.00552  3:0.11311  4:0.88125
random expectation: 1:0.0625 2:0.25 3:0.375 4:0.25 over all 2^32 differences
```

Two caveats that must not be dropped:

1. At 5 bits per word the model is dominated by carry artefacts of the
   truncation, so this is a **sanity check that the structure behaves**, not a
   distinguisher bound.
2. The random-permutation comparison in the tool is per fixed input difference
   and is not a like-for-like distinguisher statement. A real distinguisher
   claim would need a proper truncated-differential argument at full width.

The exact-zero `P[weight 0]` result is the part worth keeping, because it is
the computational confirmation of the zero-column result above.

## What this document does not establish

- No full-width differential or linear bound. Neither is computable here.
- No bound on differential-hull accumulation, boomerang, or related-key
  behaviour of the key schedule.
- No independent review. The cross-checks in this document prove the probe
  measures the shipped code correctly. They say nothing about whether the
  shipped code is secure.
- No side-channel result. The separate timing and assembly observations live in
  `docs/v3_side_channel_audit.md` and are a separate, still-open item.

The correct one-sentence status: **the reduced-width differential and linear
families were measured exactly and show no break, the differential and absolute
linear tables were proven key-independent, the zero column is empty, and no
24-round trail uses fewer than 48 of 96 F evaluations; the full-width families
and the external review remain open.**

## Reproducing

```bash
# fast regression run used in CI
cargo run --release --manifest-path analysis/ddt-probe/Cargo.toml -- \
  --width 12 --key-independence \
  --assert-diff-log2 4 --assert-zero-log2 1 --assert-corr-log2 2

# full self-test of the tool, including Parseval and row-sum identities
cargo test --release --manifest-path analysis/ddt-probe/Cargo.toml

# the measurements recorded in this document
cargo run --release --manifest-path analysis/ddt-probe/Cargo.toml -- \
  --width 14 --cross-check 200000 --cross-check-blocks 500

# reduced-block truncated screen (slow, about 30 s at width 5)
cargo run --release --manifest-path analysis/ddt-probe/Cargo.toml -- \
  --skip-ddt --skip-lat --reduced-block 5
```
