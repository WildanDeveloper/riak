# RIAK v0.3 Candidate Specification

**Status: experimental research candidate — not approved for real data.**

This version was created as a precautionary full-diffusion redesign after the
v0.2 candidate remained unvalidated. v0.2 remains available for reproducibility,
but it must not be treated as a viable replacement. No deterministic v0.2 outer
invariant is claimed; see `docs/riak_v3_analysis.md` for the correction of an
earlier analysis mistake.

## Parameters

- Block: 128 bits (`[u32; 4]`)
- Key: 512 bits (`[u32; 16]`)
- Outer rounds: 24
- Sub-updates per outer round: 4
- Round function: 32-bit custom ARX/multiplication function inherited from the
  v0.2 research definition
- No data-dependent branches, table lookups, or standard cryptographic
  primitives in the core

All word arithmetic is modulo `2^32`; rotations are rotate-left.

## Full-diffusion outer network

For one outer round, with input words `x0,x1,x2,x3`, round key `k`, and public
slot constants `c0..c3`, compute sequentially:

```text
y0 = x0 XOR F(x1 XOR x2 XOR x3, k, c0)
y1 = x1 XOR F(y0 XOR x2 XOR x3, k, c1)
y2 = x2 XOR F(y1 XOR y0 XOR x3, k, c2)
y3 = x3 XOR F(y2 XOR y1 XOR y0, k, c3)
```

The next round starts from `[y0,y1,y2,y3]`. The update is invertible in
reverse order:

```text
x3 = y3 XOR F(y2 XOR y1 XOR y0, k, c3)
x2 = y2 XOR F(y1 XOR y0 XOR x3, k, c2)
x1 = y1 XOR F(y0 XOR x2 XOR x3, k, c1)
x0 = y0 XOR F(x1 XOR x2 XOR x3, k, c0)
```

This is deliberately not the old one-branch-at-a-time sliding Feistel. Every
sub-update consumes already updated words, so a one-bit input change was
observed to affect all four output branches after one outer round.

### Public constants

The 24 round primes are:

```text
2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89
```

The four slot masks are:

```text
c(r,0) = P[r] XOR 0x00000000
c(r,1) = P[r] XOR 0x13579BDF
c(r,2) = P[r] XOR 0x2468ACE0
c(r,3) = P[r] XOR 0xFEDCBA98
```

These are public domain-separated constants, not secrets.

## F and key schedule

The current source revision is `0.3-candidate-r2`; the `r2` label records the
nonlinear round-key extraction revision described below.

F is the v0.2 candidate F: three odd modular multiplications separated by
full-rank GF(2) xorshift/rotate layers and modular additions. Its exact
constants and operations are documented in `docs/riak_v2.md` and implemented in
`src/v2.rs`; v0.3 reuses that function while replacing the outer network.

For state `A[0..15]`, domain `D`, and round `r`, the current v0.3 schedule
sweeps all sixteen words. For `i = 0..15`:

```text
q = A[(i+3) mod 16] XOR ROTL(A[(i+7) mod 16], 11)
    XOR ROTL(A[(i+13) mod 16], 5)
c_i = P[r] XOR SLOT[i mod 4] XOR (i * 0x01000193)
A[i] = A[i] XOR F(q, D, c_i)
```

The round key is then extracted through a fixed sixteen-step nonlinear fold.
With `t_(-1) = D XOR (P[r] * 0x9E3779B9)` and
`c'_i = P[r] XOR SLOT[i mod 4] XOR (i * 0x01000193) XOR 0x13579BDF`:

```text
t_i = F(t_(i-1) XOR A[i], D XOR (i * 0x01000193), c'_i)
rk[r] = t_15
```

The earlier full-sweep revision used a four-word XOR extraction. A structured
multi-bit related-key screen found exact round-key cancellation for that
revision, so the nonlinear extraction above is now mandatory. The old sparse
schedule and the four-word extraction are not the schedule described here.
Neither this mitigation nor the screens are a related-key proof.

The standalone block API uses `D = DOMAIN_DEFAULT = 0`. The wrapper uses
`DOMAIN_RACIK = 0x52414349` and `DOMAIN_MAC = 0x4D414349`. Local schedule
state and byte-key conversion arrays are best-effort cleared after expansion;
this is not a formal guarantee against compiler/platform copies.

## Experimental v0.3 wrapper

`RiakV3Cipher` is a custom encrypt-then-authenticate research wrapper. It is
not standardized AEAD and has no external security claim.

### Racik confidentiality mode

For nonce `N` (12 bytes), with `enc` denoting the domain-separated v0.3 block
cipher:

```text
S0 = E_enc(N || "RIC3")
for block i:
    T_i = S_i with word0 += i
    Z_i = E_enc(T_i)
    C_i = P_i XOR Z_i
    S_(i+1) = E_enc(C_i XOR A XOR S_i)
A = 0xA5A5A5A5 on every word
```

The final partial block uses the available bytes only for the XOR output; the
absorbed block is zero-padded before the state transition. Nonce reuse with the
same key is forbidden: it exposes the usual CTR first-block XOR relationship
and can make later state/keystream relationships predictable.

### Custom authentication tag

The tag is a separate-domain v0.3 CBC-MAC over the exact byte string:

```text
"RIAK3CUSTOM-v03\\0" ||
nonce ||
u64_le(aad_len) ||
u64_le(ciphertext_len) ||
aad ||
ciphertext
```

The total authenticated input length is also encoded in the initial MAC block;
the final block is zero-padded. `open` computes and compares all 16 tag bytes
with a fixed-length constant-time equality routine before decrypting or
returning plaintext. AAD, nonce, ciphertext length, and ciphertext content are
all bound. The library API is one-shot and the caller supplies the complete
AAD; the CLI authenticates `magic || nonce` as AAD.

The mode and tag are still experimental because the custom block cipher and
this mode have not passed the complete cryptanalysis, side-channel, and
external-review gates.

## CLI format

`v3enc` writes:

```text
"RIAK3C" || nonce(12) || ciphertext || tag(16)
```

`v3dec` checks the magic, authenticates the header as AAD, verifies the tag
before decryption, and rejects modified nonce, ciphertext, tag, or header.
`v0.1` (`RIAK1`) and v0.2 (`RIAK2C`) commands remain available as legacy
research formats.

## Deterministic labeled sample

For a reproducible test (public test key and fixed nonce only), run:

```text
cargo run --release --example v3_sample -- wildan
```

The tool prints separate `plaintext_hex`, `ciphertext_hex`, `tag_hex`, and
`riak3c_file_hex` fields. The lowercase `wildan` sample has ciphertext
`9d638a5e52b6`, tag `8a9002a6b127aa2b0c69d1bc987782b9`, and file hex:

```text
5249414b3343101112131415161718191a1b9d638a5e52b68a9002a6b127aa2b0c69d1bc987782b9
```

The CLI itself generates a fresh random nonce, so its exact bytes will differ.

## Reproducibility

- Rust implementation: `src/v3.rs`
- Independent Python reference: `simulator/riak_v3.py`
- Block vectors: `tests/v3_vectors.rs`
- Wrapper vectors: `tests/v3_cipher_vectors.rs`
- Generated Python/Rust wrapper cross-check: `tests/v3_fuzz_vectors.rs`
  and `simulator/generate_v3_vectors.py`
- CLI integration: `tests/cli_v3.rs`
- Deterministic labeled sample: `examples/v3_sample.rs`
- Screens: `examples/v3_probe.rs`, `v3_avalanche.rs`, `v3_differential.rs`,
  `v3_linear_trail_search.rs`, `v3_linear_hull.rs`, `v3_full_linear.rs`,
  `v3_trail_search.rs`, `v3_related.rs`, `v3_related_multibit.rs`,
  `v3_key_schedule_analysis.rs`, `v3_timing.rs`, and `v3_bench.rs`
- Side-channel audit: `docs/v3_side_channel_audit.md`
- Analysis record: `docs/riak_v3_analysis.md`

No v0.3 security gate is considered closed by the existence of these tests or
screens.
