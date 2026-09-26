# RIAK v0.3 Analysis Record

Date: 2026-09-25

This is a screening record, not a proof of security. The current v0.3 source
revision is `0.3-candidate-r2` and is not approved for real data.

## v0.2 status and analysis correction

The v0.2 outer update is a sparse shift/update:

```text
Y0 = X1
Y1 = X2
Y2 = X3
Y3 = X0 XOR F(X1 XOR X2 XOR X3)
```

An earlier draft of this record incorrectly claimed that
`X1 XOR X2 XOR X3 == Y1 XOR Y2 XOR Y3` was an unconditional invariant. That
claim used the wrong output-word indices and was falsified by a direct Rust
check. **No deterministic v0.2 outer invariant is asserted here.** v0.2 remains
unvalidated and is rejected for production use because its complete security
gates were not passed, not because of the disproved relation.

v0.3 was created as a precautionary full-diffusion redesign: every output
branch is updated from already updated branches, avoiding the sparse v0.2
outer structure. This is a design goal, not a proof that v0.2 was broken or
that v0.3 is secure.

## v0.3 structural checks

- The sequential four-sub-update network has an explicit reverse inverse.
- One-round tests cover all 32 bit positions in each of four input branches and
  confirm that a one-bit change reaches every output branch in the test cases.
- `F` retains the v0.2 full-rank mixer and odd-multiplier checks.
- Domain-separated key schedules produce distinct representative outputs.
- The first sparse v0.3 schedule was rejected after a 4,096-case one-bit
  related-key screen found 47,779 zero round-key difference cells. Its formula
  was `s=A0 XOR ROTL(A5,7) XOR A11; s=F(s,P,D); A0^=s; rotate(A); rk=s^A3^A9`.
  It was replaced by a sixteen-word nonlinear sweep; that old schedule is not
  the schedule described in the current v0.3 specification.
- The sixteen-word sweep initially extracted round keys as a four-word XOR.
  A new structured multi-bit screen found 111 zero round-key difference cells
  in 98,304 cells for the all-ones cross-word family (4,096 cases), including
  deterministic first-round cancellation for word pairs `(0,6)`, `(3,13)`, and
  `(5,15)`. This was a real related-key weakness, not a pass criterion.
- The current revision replaces that linear extraction with a fixed sixteen-step
  nonlinear fold over the complete state. Regression cases for those pairs are
  in `src/v3.rs`; the new multi-bit screen is recorded below and remains only a
  bounded screen.
- Rust/Python block vectors: 12/12 match.
- Rust/Python custom wrapper vectors: 4/4 match.
- 128 generated Python-reference wrapper cases match Rust and round-trip
  successfully.

These are implementation and structural checks only.

## Avalanche smoke screen

Command:

```text
cargo run --release --example v3_avalanche 512
```

At 24 rounds, the sampled plaintext flip average was `63.83` differing output
bits (minimum `48`), and the one-bit related-key average was `63.34` (minimum
`47`). One-round averages were `60.20` and `64.16`, respectively. These are
diffusion sanity statistics, not a proof of full diffusion or key independence.

## Full-block empirical differential screen

Command:

```text
cargo run --release --example v3_differential 262144
```

For five input differences and round counts `1,2,4,6,8,12,24`, the top sampled
output cell had one hit in every tested 262,144-pair cell. This is a larger
sampling screen; it does not bound all differences or all output differences,
and it does not rule out rare characteristics.

## Structured linear screens

Commands:

```text
cargo run --release --example v3_probe
cargo run --release --example v3_linear_trail_search 16384 16
cargo run --release --example v3_linear_hull 16384 12 8
cargo run --release --example v3_linear_hull 16384 16 8
cargo run --release --example v3_full_linear 4096
```

The full structured probe at 2,048 samples/pair reported a maximum absolute
structured bias of `0.042969` in the sampled family. The larger true-vector
screen at 4,096 samples/pair reported a maximum sampled absolute bias of
`0.025391` at four rounds and `0.021484` at 24 rounds. These are sample maxima,
not bounds.

The bounded v0.3 outer-network trail search used 16 masks and 16,384 samples
per F mask pair, per round, per slot. The strongest non-trivial sampled
one-sub-update correlation was `0.036377`; the strongest trail found within the
finite mask subset had estimated magnitude `2^-12.023` and used two non-trivial
F sub-updates plus trivial zero-mask transitions. This is a reason to perform a
larger, independently seeded hull search, not a reason to claim a break or a
bound. The tool is explicitly not a full LAT or linear-hull result.

The bounded signed hull search used a closed 8-mask GF(2) subspace, 16,384
samples per F mask pair/round/slot, and eight single-branch input masks. The
largest sampled absolute hull among those inputs was about `4.99e-9`
(`2^-27.58`). A wider closed 4-dimensional, 16-mask subspace at the same
sample count gave a maximum of about `3.77e-11` (`2^-34.63`). This is useful
evidence against a catastrophic correlation in those subspaces, but it is
still a tiny, sampled family and not a full 128-bit LAT/hull bound.

The hull tool treats sampled per-subupdate correlations as a transition
model; it does not account for all statistical dependencies or the complete
128-bit LAT.

The true-vector screen used 32 random 128-bit input/output mask pairs and
4,096 samples per pair. The maximum sampled absolute bias was `0.025391` at
four rounds and `0.021484` at 24 rounds; these are sample maxima, not bounds.

The disproved v0.2 outer-invariant claim is not used as a v0.3 result; the
finite screens above do not establish full diffusion security.

## Differential trail search

Command:

```text
cargo run --release --example v3_trail_search 4096 100000 4
```

The measured family contained 531 one/two-bit and old-mask input differences,
with four sampled output differences per input; the DFS also samples new input
differences on demand. The F table uses one representative key/constant, not a
per-round/per-slot table. The bounded run explored 100,001 nodes, exhausted its
budget, and found a best sampled trail of approximately `2^-1138` (the first
nontrivial transitions were at the `2^-12` sample floor). This is far below the
usual security threshold in this bounded model, but it is not a proof: a larger
DDT table, more output candidates, multiple keys, and independent trail
construction are still required. A deeper 16,384-sample, 500,000-node run with
eight outputs per input on the current revision found a best sampled trail of
approximately `2^-1317`, also not a proof.

## Related-key smoke probe

Command:

```text
cargo run --release --example v3_related 4096
```

For 4,096 one-bit key changes and four blocks per change:

- average output Hamming distance: `64.034`
- minimum: `42`
- maximum: `85`
- zero-difference output blocks: `0`

This only rules out the simplest catastrophic smoke failure. The dedicated
`v3_related_multibit` screen below adds structured multi-bit, cross-word, and
domain-crossing families, but neither tool is a full related-key linear/differential
proof.

## Key-schedule/related-key screen

Commands:

```text
cargo run --release --example v3_key_schedule_analysis 16384
cargo run --release --example v3_related_multibit 16384
```

The first sparse v0.3 schedule was rejected after the original screen measured
47,779 zero round-key difference cells over 4,096 one-bit key changes. The
next full-sweep revision passed that one-bit screen but was subsequently
rejected after the multi-bit screen found exact first-round cancellation for
all-ones differences across word pairs `(0,6)`, `(3,13)`, and `(5,15)`.

The current sixteen-step nonlinear extraction measured with 16,384 cases:

- one-bit round-key average Hamming distance: `16.005` (minimum `4`, zero cells
  `0`)
- actual related-key block output average: `63.995` bits, minimum `41`, zero
  cases `0`
- domain-separation average round-key Hamming distance: `15.708`, minimum `9`
- related-key linear screen maximum absolute bias: `0.024170`
- structured deltas (1-bit, high-bit, all-one, and old masks across five word
  positions): average `15.993`, minimum `4`, zero cells `0/184,320`

The multi-bit screen additionally exercised eight one-word/cross-word delta
families and all three public domains. In its 16,384-case run, the formerly
catastrophic all-ones family measured zero round-key cells `0`, with block
output zero cases `0`; the largest sampled related-key linear bias was
`0.041016`. A deeper 65,536-case run also measured zero round-key cells for
all eight families and all domain pairs (maximum sampled linear bias
`0.044922`). These are bounded screens, not a related-key security bound or a
key-recovery result. The nonlinear extraction is a mitigation for the observed
failure, not a proof that all related-key trails are absent.

## Wrapper checks

- Empty, partial, full, and multi-block seal/open cases pass.
- Ciphertext, nonce, magic, wrong AAD, and wrong-key rejection pass in unit and
  CLI tests.
- Tag verification precedes plaintext return.
- The authenticated input binds context, nonce, AAD length, ciphertext length,
  AAD, and ciphertext bytes.
- The v0.3 state transition binds both prior state and absorbed ciphertext;
  it does not use the v0.1 `Z XOR C = P` collapse.
- Constant-time tag comparison uses a fixed 16-byte loop.
- Output files are written through a same-directory temporary file and
  atomic rename with mode `0600` on Unix; symlink/hardlink targets are not
  followed. CLI key files are rejected if group/world readable, checked and
  read through one descriptor, symlinks are rejected, and raw `--key` is
  rejected. CLI input is limited to 64 MiB.

Nonce reuse remains forbidden and is not made safe by the custom tag.

## Performance snapshot

On the development host, `cargo run --release --example v3_bench` reported
approximately:

- block encryption: approximately `24–25 MiB/s`
- four-way interleaved block: approximately `60–64 MiB/s` across runs
- key schedule setup: approximately `3.5–3.8 µs` per cipher after the
  nonlinear extraction change
- seal: approximately `8.0–8.2 MiB/s`
- open: approximately `8.0–8.2 MiB/s`
- measured x4 speedup over single-block: approximately `2.4–2.5×`

The four F calls per outer round are a deliberate diffusion/performance
tradeoff. The `x4` API explicitly unrolls four independent lanes; this improved
measured block throughput without changing single-block or wrapper semantics.
This benchmark is not a constant-time measurement.

## Audit remediation after `/root/severity.riak`

The legacy/operational findings were addressed as follows:

- v0.1 `enc`/`dec` aliases are rejected; the broken format is reachable only
  through the opt-in `legacy-v1` feature and explicit `legacy-enc`/`legacy-dec`
  commands.
- The legacy CLI tag now binds the magic/header, nonce, and ciphertext length.
  The v0.1 primitive and its `Z XOR C = P` mode remain intentionally broken;
  this is quarantine, not a cryptographic repair.
- Output files use a same-directory `create_new` temporary file followed by
  atomic rename, so symlink and hardlink targets are not followed.
- Raw `--key` argv is rejected. Key files are opened once, checked on that file
  descriptor, and read from that same descriptor.
- CLI and v0.2/v0.3 wrapper inputs have a 64 MiB ceiling.
- v0.1, v0.2, and v0.3 now perform best-effort round-key/local-word clearing.
- v0.2/v0.3 expose `seal_with_sequence` backed by `NonceSequence` for
  stateful counter nonces; the legacy caller-supplied nonce API remains
  misuse-sensitive by design.

Nonce reuse on the legacy stateless API remains an API-level prohibition; it
cannot be detected reliably without stateful nonce tracking. The v0.1 linear
break, v0.1 mode collapse, and the custom v0.3 security gates are not claimed
fixed by these operational mitigations.

## Open security gates

1. Full or statistically justified LAT coverage and linear-hull analysis.
2. Multi-round differential trail search with per-round/key bounds.
3. Related-key differential and linear analysis of the key schedule.
4. Compiler/assembly and timing side-channel review of v0.3 and the wrapper
   (initial source/one-host assembly review is recorded in
   `docs/v3_side_channel_audit.md`; statistical leakage testing remains open).
5. Formal mode/tag audit, including nonce-reuse and partial-block behavior.
6. Independent external cryptanalysis and source review.

Until these gates are passed by independent reviewers, v0.3, `RIAK3C`, and
`RiakV3Cipher` remain experimental.
