# RIAK v0.3 Impossible-Differential and Boomerang Screen

Date: 2026-09-26

Tool: `examples/v3_impossible_boomerang.rs`

**Bounded screen. Not a differential bound and not a boomerang attack.** This
document records two measurements and is explicit about the gap between them.

## 1. Impossible differentials

A block difference that can never reach zero output difference is a
distinguisher on its own: it proves the cipher family is not differentially
uniform. If such a trail existed, an attacker could distinguish RIAK from a
random permutation without recovering any key.

The structural fact that makes this screen meaningful is already established in
`docs/riak_v3_ddt_lat.md`: the round function `F` is a bijection, so **the DDT
zero column is exactly empty**. An active F evaluation can never return a zero
difference. That does not automatically propagate to the full 24-round cipher,
because differences combine across branches and rounds, so the full cipher is
tested directly.

Method: for each structured input difference, encrypt 20000 random plaintext
pairs under a fresh random key and count the cases where the two ciphertexts
coincide.

```text
structured differences tested:  143
plaintext pairs per difference: 20000
total pairs:                   2860000
output differences equal to zero: 0
RESULT: no impossible differential was observed
```

Coverage of the difference family: every single-bit difference in all four
words (128), every single-word all-ones difference (4), the all-words
difference (1), every two-word combination (6), and every three-word combination
(4).

**This is an absence of observation over 2.86 million pairs, not a proof of
absence.** A rare impossible differential with probability below the sampling
floor would not be found. The test is worth running because a dead difference
would be a serious finding and none appeared, not because it settles the
question.

## 2. Differential convergence by round count

A boomerang attack needs a forward differential covering some prefix of rounds
and a backward differential covering the rest, meeting in the middle. The
staging question is how strong a single differential can be at small round
counts. The full DDT is not computable, so this measures the **empirical**
probability of the best-matching output difference for one fixed input
difference, over 4096 samples of random key and plaintext pairs.

Input difference `[80000000, 00000000, 00000000, 00000000]`:

| rounds | best count | probability |
|---|---|---|
| 1 | 1 | 0.000244 |
| 2 | 1 | 0.000244 |
| 4 | 1 | 0.000244 |
| 6 | 1 | 0.000244 |
| 8 | 1 | 0.000244 |
| 12 | 1 | 0.000244 |
| 16 | 1 | 0.000244 |
| 20 | 1 | 0.000244 |
| 24 | 1 | 0.000244 |

The best count is 1 at every round count. The output difference never converges
on a preferred value, even at one round, so there is no accumulating bias for a
trail to build on. For a random permutation over thousands of samples the best
count is also expected to be small, so this confirms "no anomalous convergence",
not "proven small probability".

## What this screen does not establish

- **It measures one input difference.** A differential bound requires analysing
  all of them, and the space is not enumerable.
- **A low measured probability is not a proven low probability.** 4096 samples
  only rule out probabilities above roughly `2^-11`; a boomerang needs trails
  far below that, and this measurement cannot see them.
- **No boomerang distinguisher was constructed or run end to end.** The two
  halves of a boomerang are not searched for here.
- **The full-width differential and linear hull bounds remain open**, as do
  adaptive techniques such as the partial-sum and square-in-square attacks,
  which a fixed-difference sample cannot represent.

## Correct one-sentence status

**No impossible differential was observed over 2.86 million pairs across 143
structured differences, and the output difference shows no convergence at any
round count for the tested input difference; no differential bound and no
boomerang distinguisher is claimed.**

## Reproducing

```bash
cargo run --release --example v3_impossible_boomerang
```
