# RIAK v0.3 Related-Key Analysis of the Key Schedule

Date: 2026-09-26

Tool: `examples/v3_related_key_schedule.rs`

**Bounded screen. Not a proof of related-key security.** This document records
what was measured, what the numbers mean, and what they do not rule out.

## Why this gate mattered

The v0.3-r1 schedule was rejected during development because a structured
multi-bit key difference left round-key difference cells at exactly zero. A
single zero round key lets a related-key attacker hold one round's key fixed
while influencing the others, which is the setup for the standard related-key
attacks against key schedules. The v0.3-r2 schedule replaced the extraction with
a fixed 16-step nonlinear fold. That replacement was a **mitigation based on a
sampling screen**, not on analysis of the failure mode.

This document re-tests the failure mode systematically.

## Method

The tool reconstructs the key schedule from the published specification and
verifies the reconstruction against the shipped implementation, by encrypting
random blocks with a locally re-implemented block cipher driven by the
re-derived round keys and comparing to `riak::v3::RiakV3`:

```text
schedule reconstruction cross-check: OK (64 random key/block cases)
```

The round keys themselves are private, so this indirect check is the only way to
confirm the tool is measuring the shipped schedule rather than its own
misreading of it. Every result below depends on that check passing.

Three questions are then asked.

### 1. Cancellation

For a key difference `D`, is any round key identical between `K` and `K ^ D`?

### 2. Avalanche

How many bits of each round-key difference are set? A schedule that leaves many
bits uninfluenced by a one-bit key change hands an attacker low-entropy round
keys. The decisive statistic is the **mean weight across all round keys**, not
the minimum: one light round key among 24 heavy ones is far less useful than a
difference that stays light throughout.

### 3. Non-affinity

If the schedule were affine in the master key, `rk(K ^ D) ^ rk(K)` would be
independent of `K`. An affine key schedule is trivially invertible by a
related-key attacker, so the test is: does one fixed difference produce
different round-0 differences under different base keys?

## Coverage

- **All 512 single-bit key differences**, for 3 base keys, across all 3 public
  domains (`DOMAIN_DEFAULT`, `DOMAIN_RACIK`, `DOMAIN_MAC`).
- **9 structured multi-bit families**, including the shapes that broke the
  earlier schedules: XOR across all words, all-ones, all-zeros-but-one-word,
  alternating, the sparse `words 0,3,9,13` family, and single-bit-per-word.
- **Non-affinity** with a multi-word difference.

## Results

### Cancellation: none found

```text
difference evaluations:  1563
zero round-key cells:    0
```

Across every family, base key, and domain tested, no round key was identical
between related keys. The weakness class that rejected v0.3-r1 does not appear.

### Avalanche: matches a uniform random difference

110592 round-key cells from the single-bit family:

```text
mean round-key weight:  16.00 of 32 bits
cells with weight < 8:  103 (0.093%)
```

A uniformly random 32-bit difference has mean weight 16.00. The measured mean
matches it to two decimal places, and only 0.093% of cells fall below weight 8.
The full histogram is a clean unimodal curve centred on 16, with observed weights
from 5 to 28.

This is the strongest positive result in the document. It says a one-bit change
to the master key produces a round-key difference that is, in distribution,
indistinguishable from a random 32-bit value. The earlier "minimum weight 5"
figure that first looked like a lead is one cell out of 110592, not a systematic
under-diffusion.

### Non-affinity: confirmed

```text
one difference, 3 base keys, distinct round-0 differences: 3
```

The round-0 difference varies with the base key, so the schedule is not affine
in the master key.

## What this does not establish

- **The difference space is not covered.** These are 1563 fixed differences out
  of `2^512`. An adaptive or multi-key related-key strategy is not modelled at
  all; a fixed-difference analysis cannot express "choose the next difference
  based on the previous result".
- **Avalanche is not a bound.** A matching weight distribution is strong evidence
  of good diffusion in the key schedule. It is not a proof, and it says nothing
  about the block cipher's own differential or linear behaviour.
- **No related-key distinguisher was constructed or run.** This screen looks for
  a structural defect, not for an attack.
- **Related-key security of the schedule remains unproven** and is listed as an
  open gate in `docs/external_review_packet.md`.

## Correct one-sentence status

**The v0.3-r2 key schedule shows no round-key cancellation and a round-key
difference distribution indistinguishable from random across 1563 tested key
differences, and it is provably non-affine in the master key; the full related-key
space and adaptive multi-key strategies remain unanalyzed.**

## Reproducing

```bash
cargo run --release --example v3_related_key_schedule
```
