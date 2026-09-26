# RIAK v0.3 External Review Packet

**Purpose:** give an independent cryptographer enough material to reproduce the
implementation and attack the current candidate. This packet is not a request
to assume the candidate is secure.

**Status:** RIAK v0.3 and `RIAK3C` are experimental and unaudited. Do not use
them for real data. The project intentionally uses a custom construction and
does not use a standard cipher/AEAD as its core.

## 1. Scope and versioning

- v0.1: legacy `RIAK1`, known deterministic linear break; retained for
  reproducibility and marked deprecated.
- v0.2: isolated `riak::v2`, unvalidated and rejected for production; an
  earlier claimed unconditional outer invariant was incorrect and is not used
  as evidence.
- v0.3: current isolated candidate in `riak::v3` (`0.3-candidate-r2`);
  full-diffusion outer network, revised full-sweep key schedule, and nonlinear
  round-key extraction. It has not passed external review.

Relevant source:

- `src/v3.rs`
- `src/main.rs` (`v3enc`/`v3dec`)
- `simulator/riak_v3.py`
- `docs/riak_v3.md`
- `docs/riak_v3_analysis.md`
- `docs/v3_side_channel_audit.md`
- `examples/v3_related_multibit.rs`
- `tests/v3_fuzz_vectors.rs` and `simulator/generate_v3_vectors.py`

## 2. Candidate parameters

- Block: 128 bits, four `u32` words
- Key: 512 bits, sixteen `u32` words
- Outer rounds: 24
- Sub-updates: 4 per outer round
- Tag: 16 bytes
- Nonce: 12 bytes
- Arithmetic: wrapping modulo `2^32`

The exact F operations and constants are in `docs/riak_v2.md` and
`src/v2.rs`. v0.3 reuses that F but must be reviewed as part of the new cipher,
not assumed secure because its mixers are full rank.

## 3. Outer network to review

For each round, with `x0..x3`, key `k`, and public constants `c0..c3`:

```text
y0 = x0 XOR F(x1 XOR x2 XOR x3, k, c0)
y1 = x1 XOR F(y0 XOR x2 XOR x3, k, c1)
y2 = x2 XOR F(y1 XOR y0 XOR x3, k, c2)
y3 = x3 XOR F(y2 XOR y1 XOR y0, k, c3)
```

Reverse the four updates to decrypt. Please look for linear invariants,
impossible/boomerang trails, differential propagation through sequential
updates, and any dependency that survives multiple outer rounds.

## 4. Key schedule to review

For each round and word index `i=0..15`:

```text
q = A[(i+3) mod 16] XOR ROTL(A[(i+7) mod 16],11)
    XOR ROTL(A[(i+13) mod 16],5)
c_i = P[r] XOR SLOT[i mod 4] XOR (i * 0x01000193)
A[i] = A[i] XOR F(q, D, c_i)
```

The current round-key extraction is a fixed nonlinear fold over the complete
state. Let `t = D XOR (P[r] * 0x9E3779B9)`, then for every `i=0..15`:

```text
c'_i = P[r] XOR SLOT[i mod 4] XOR (i * 0x01000193) XOR 0x13579BDF
t = F(t XOR A[i], D XOR (i * 0x01000193), c'_i)
rk[r] = t
```

`D` is `0` for standalone block use, `DOMAIN_RACIK` for confidentiality, and
`DOMAIN_MAC` for authentication. The earlier sparse schedule and the
four-word XOR extraction are not the current schedule. A structured multi-bit
related-key screen found exact round-key cancellation in the latter; the
nonlinear extraction is a mitigation, not a proof.

## 5. Wrapper to review

Confidentiality state:

```text
S0 = E_enc(nonce || "RIC3")
T_i = S_i with word0 += i
Z_i = E_enc(T_i)
C_i = P_i XOR Z_i
S_(i+1) = E_enc(C_i XOR 0xA5A5A5A5 XOR S_i)
```

Authentication input:

```text
"RIAK3CUSTOM-v03\0" ||
nonce || u64_le(aad_len) || u64_le(ciphertext_len) ||
aad || ciphertext
```

The MAC is a CBC-MAC under `DOMAIN_MAC`, with an initial encoded total-length
block and zero-padded final block. `open` verifies the tag before invoking
confidentiality decryption. The CLI authenticates `magic || nonce` as AAD.

Review specifically:

- nonce reuse and state recovery;
- partial-block and empty-message handling;
- length/AAD concatenation ambiguity;
- tag forgery, truncation, extension, and wrong-key behavior;
- whether the custom mode has a justified security argument;
- release-mode error behavior and whether any plaintext is exposed on failure;
- CLI key-file permission handling (`--key-file` is required; raw `--key` is
  rejected; the file is checked and read through one descriptor).

## 6. Reproduction commands

From `/root/riak`:

```text
cargo test --release --all-targets
cargo test --release --features legacy-v1 --test cli_legacy
python3 simulator/riak_v3.py
scripts/ci.sh
```

Vectors:

```text
tests/v3_vectors.rs
tests/v3_cipher_vectors.rs
python3 simulator/generate_v3_vectors.py
# Rust then checks tests/v3_fuzz_vectors.rs
```

Screens:

```text
cargo run --release --example v3_sample -- wildan
cargo run --release --example v3_probe
cargo run --release --example v3_avalanche 512
cargo run --release --example v3_differential 262144
cargo run --release --example v3_linear_trail_search 16384 16
cargo run --release --example v3_linear_hull 16384 12 8
cargo run --release --example v3_linear_hull 16384 16 8
cargo run --release --example v3_full_linear 4096
cargo run --release --example v3_trail_search 4096 100000 4
cargo run --release --example v3_related 4096
cargo run --release --example v3_key_schedule_analysis 16384
cargo run --release --example v3_related_multibit 16384
cargo run --release --example v3_timing
cargo run --release --example v3_bench
```

The screens are intentionally labeled bounded/sampled. A reviewer should rerun
with independent seeds, larger sample sizes, and independently implemented
models rather than treating the outputs as bounds.

## 7. Known limitations and open findings

- Full 2^32 LAT enumeration is computationally infeasible; current LAT/hull
  tools cover finite structured families only.
- The strongest bounded trail/hull results are not proofs and may be sampling
  noise; the current differential screen found only a very low estimated
  `2^-1138` trail in its sampled family; a deeper current-revision run reached
  approximately `2^-1317`, while larger searches and independent implementations
  are still required.
- Related-key analysis currently consists of smoke screens, not a full
  differential/linear key-schedule proof.
- `dudect`, `ctgrind`, `valgrind`, and `perf` were unavailable in the current
  environment. One-host assembly inspection and a rough timing run are recorded
  in `docs/v3_side_channel_audit.md`, but statistical leakage testing is open.
- The custom mode and tag have no formal AEAD proof.
- Nonce reuse is forbidden; the construction does not make reuse safe.
- The block cipher is not a replacement for an audited standard primitive.

## 8. Independent review checklist

Please report reproducible findings, not only theoretical concerns:

- [ ] Verify Rust/Python block and wrapper vectors independently.
- [ ] Derive linear masks across the sequential outer network; search for an
      exact invariant, not only random masks.
- [ ] Implement an independent DDT/LAT engine and test full sub-updates with
      per-round keys and constants.
- [ ] Search multi-round differential and boomerang trails across the outer
      network, including inactive/zero-difference branches.
- [ ] Analyze related-key differences through all 16 key-schedule words and
      domain changes; test structured key differences, not just one-bit flips;
      specifically retry all-ones cross-word differences and related nonlinear
      extraction trails.
- [ ] Attempt nonce-reuse, truncation, extension, AAD, and tag-forgery attacks.
- [ ] Inspect optimized assembly on at least one independent compiler/target;
      run a statistical timing leakage test.
- [ ] Check key/zeroization and error paths for plaintext/key leakage.
- [ ] Do not infer safety from passing tests; report assumptions and confidence.

## 9. Reporting format

For each finding, include:

1. affected version and file/line or exact equation;
2. key/nonce/plaintext setup;
3. attack steps and expected/observed measurements;
4. whether the result is deterministic, statistical, or heuristic;
5. a minimal reproducer and proposed mitigation;
6. whether old vectors must be regenerated after the mitigation.

Until an independent review team signs off on the results, the correct status
is **experimental / rejected for production use**.
