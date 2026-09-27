# RIAK v0.3 First-Order Timing Signal: Diagnosis

Date: 2026-09-27

Tools: `examples/v3_leakage.rs`, `examples/v3_leakage_diagnose.rs`

**Conclusion up front: the fixed-vs-random timing signal is not attributable to
the RIAK cipher. A duration-matched chain of plain wrapping additions, with no
cipher logic at all, produces a larger bias than RIAK does. This document
records the measurement, the mistake that had to be corrected to get there, and
what is still not established.**

## The original signal

`examples/v3_leakage.rs` measures `encrypt_block` on a fixed-plaintext class
against a random-plaintext class, with the class order randomised each round,
and reports Welch's `t`. Five runs at 1.5M samples, pinned with `taskset` and
raised with `chrt`:

| run | fixed-vs-random t | negative control t |
|---|---|---|
| 1 | -4.95 | -2.60 |
| 2 | -3.45 | -1.50 |
| 3 | -5.07 | -0.01 |
| 4 | -4.84 | -1.02 |
| 5 | -5.40 | -1.49 |

The consistent negative sign, with a negative control that stayed near zero, was
initially read as a genuine first-order timing signal in the block core and was
recorded as an open finding.

## Why that reading was wrong

The first diagnosis attempt compared RIAK against trivial one-instruction
functions:

| function | cycles | t | delta |
|---|---|---|---|
| XOR only | 28 | 0.02 | 0.006% |
| multiply only | 28 | -1.24 | -0.980% |
| add only | 28 | -0.56 | -0.945% |
| RIAK full round | 2056 | -12.99 | -1.943% |

Read naively this looks decisive: the trivial operations have small `t` and
RIAK has a large one. **That comparison is invalid.** A single XOR takes about
28 cycles, so a 0.3% effect is roughly a tenth of a cycle and sits underneath
the timer and scheduling noise. A short baseline cannot resolve an effect of
the size being looked for, so its small `t` carries no information. Comparing a
28-cycle measurement against a 2056-cycle one is not a like-for-like test.

The baseline has to be **duration-matched**.

## Duration-matched control

Repeating the comparison with trivial chains of the same order of length as a
RIAK round, 400k samples per class:

| function | cycles | t | delta |
|---|---|---|---|
| XOR only (short) | 28 | 0.02 | 0.006% |
| multiply only (short) | 28 | -1.24 | -0.980% |
| add only (short) | 28 | -0.56 | -0.945% |
| XOR chain (duration-matched) | 1684 | -4.93 | -0.598% |
| **add chain (duration-matched)** | **550** | **-32.58** | **-6.820%** |
| RIAK full round | 2056 | -12.99 | -1.943% |

A chain of nothing but `wrapping_add` and `xor`, with no cipher structure, no
key schedule, no S-box, and no table, produces a `t` of **-32.6** and a bias of
**-6.8%**. RIAK produces `t` of **-13.0** and a bias of **-1.9%**.

The plain addition chain is about **two and a half times stronger** than the
cipher it was supposed to be a control for. The signal is therefore a property
of the arithmetic and the machine, not of the RIAK design.

## What mechanism this is consistent with

The pattern matches the Data Power Impact effect documented in the hardware
timing literature: on a modern CPU, the power and switching activity of a
computation depend on the data values, so transitioning between differing
values costs measurably more than repeating one value. The magnitude tracks the
energy of the operation, which is why the addition chain, which has a long
carry-dependent power path, shows a larger effect than the XOR chain.

RIAK accumulates roughly a thousand arithmetic operations per round, which is
enough to make the platform-level effect rise above the measurement noise. That
is a property of running any nontrivial ARX code on this hardware, not a defect
in how RIAK is written. The cipher contains no data-dependent branch, no table
lookup, and no variable-latency instruction.

## The diversity sweep did not support what it was meant to show

A second measurement compared RIAK using 1, 2, 4, 16, 256 and 65536 distinct
fixed values against a single fixed value, on the hypothesis that the bias would
grow with the number of distinct values. Across two runs the `n = 1` row, where
both classes run the identical block and the true difference is exactly zero,
came out at -0.04% and -0.69%.

That row is a direct measurement of the harness drift, so deltas of a few tenths
of a percent in this sweep are inside the noise and no trend is established. The
output of the tool was corrected to say this rather than to claim a diversity
effect. The sweep is retained only to bound what the fixed-vs-random method can
resolve in this environment.

## What is and is not established

**Established:**

- The fixed-vs-random timing signal in v3.3 is reproducible but is **not
  attributable to the cipher design**. A trivial duration-matched addition
  chain exceeds it.
- The cipher core contains no data-dependent control flow, no table access, and
  no integer division, by source review and by the static assembly screen in
  `scripts/asm_audit.sh`.
- A negative control using two different constant blocks stays near zero, so the
  effect requires input variation rather than a constant offset.

**Not established:**

- **v0.3 is not certified constant-time.** Nothing here proves that. A
  data-dependent power effect is a real physical property of the platform, and
  this test does not measure whether it is exploitable.
- Second-order leakage, cache, port contention, speculative execution, and power
  analysis are all still uncovered.
- Only one machine, one compiler, and one target are covered. A CPU without
  aggressive power management, or a different microarchitecture, would not
  reproduce this effect at all, which also means the effect is a platform
  property rather than an algorithm property.
- The wrapper mode and tag paths remain untested by this method.

## Correct one-sentence status

**The first-order fixed-vs-random signal measured earlier is a
platform-level data-dependent power effect, demonstrated by a duration-matched
plain addition chain that exceeds it by a factor of about 2.5, so it is not a
property of the RIAK design; v0.3 is nonetheless not certified constant-time,
and statistical leakage detection, formal mode analysis, and external review
remain open.**

## Reproducing

```bash
taskset -c 0 chrt -f 5 cargo run --release --example v3_leakage -- 1500000
taskset -c 0 chrt -f 5 cargo run --release --example v3_leakage_diagnose
```

Both need to run pinned and at raised priority to produce meaningful numbers.
An unpinned run is not comparable to the tables above.
