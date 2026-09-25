# RIAK v0.2 Candidate Specification

**Status: rejected for production — not approved for real data.**

v0.2 has not passed the complete security gates. An earlier claimed
unconditional outer invariant was falsified by direct implementation checking
and is not used as evidence. This specification is retained for reproducible
research only.

This document records the first replacement candidate for the broken v0.1
round function. The v0.1 implementation remains available for reproducible
research; it is not silently overwritten.

## Parameters

- Block: 128 bits (`[u32; 4]`)
- Key: 512 bits (`[u32; 16]`)
- Rounds: 24
- Round function: 32 bits
- Network: four-branch Feistel, `X0' = X0 XOR F(X1 XOR X2 XOR X3)`

All arithmetic in the round function is modulo `2^32`. Rotations are
rotate-left. There are no data-dependent branches or table lookups.

## Candidate F

Let:

```text
MUL_A = 0x9E3779B9
MUL_B = 0x85EBCA6B
MUL_C = 0xC2B2AE35
ADD_A = 0x7F4A7C15
ADD_B = 0x1B873593
```

For input `x`, round key `k`, and public round constant `c`:

```text
t = x XOR k
t = t + c
t = t * MUL_A

t = t XOR (t >> 7)
t = ROTL(t, 11)
t = t XOR (t << 9)

t = t + ADD_A
t = t * MUL_B

t = t XOR (t >> 5)
t = ROTL(t, 7)
t = t XOR (t << 13)

t = t + ADD_B
t = t * MUL_C

t = t XOR (t >> 17)
t = ROTL(t, 19)
t = t XOR (t << 15)

F = t
```

The operations are sequential: every assignment uses the updated `t`.

### Structural properties

- `MUL_A`, `MUL_B`, and `MUL_C` are odd, so each multiplication is bijective
  modulo `2^32`.
- Each of the three xorshift/rotate layers has GF(2) rank 32; this is checked
  by a unit test over all 32 basis vectors.
- Therefore the candidate `F` is a permutation. This is a structural fact,
  not a security proof.

The implementation is in `src/v2.rs`, and the independent reference is in
`simulator/riak_v2.py`.

## Candidate key schedule

For state `A[0..15]`, domain `D`, and round `r`:

```text
s = A[0] XOR ROTL(A[5], 7) XOR A[11]
s = F(s, P[r], D)
A[0] = A[0] XOR s
A = rotate-left-one(A)
rk[r] = s XOR A[3] XOR A[9]
```

`D = 0` is used by the standalone block API; the experimental wrapper uses
separate public domains for Racik and authentication. This preserves the
history-dependent idea of v0.1 but must be analyzed again for related-key
and key-recovery properties.

## What has been checked

- Rust/Python cross-validation vectors.
- Block encrypt/decrypt round trips.
- Full-rank linear mixing layers.
- Sampled F collisions and selected differential probes.
- Old v0.1 deterministic masks no longer hold in the v0.2 sample.

## What has **not** been proved

- No usable bound on differential trails.
- No usable bound on linear trails or linear hulls.
- No related-key analysis of the key schedule.
- No side-channel measurement or compiler-level constant-time verification.
- No formal security proof for the custom mode/MAC wrapper.
- No external cryptanalysis or review.

## Experimental v0.2 confidentiality/authentication wrapper

`RiakV2Cipher` is an experimental custom wrapper around the candidate block
cipher. It is intentionally exposed as a separate API and CLI (`v2enc` /
`v2dec`); it is not a claim of standardized AEAD security.

### Racik v0.2

For nonce `N` (12 bytes):

```text
S0 = E_enc(N || "RACI")
for block i:
    T_i = S_i with word0 += i
    Z_i = E_enc(T_i)
    C_i = P_i XOR Z_i
    S_(i+1) = E_enc(C_i XOR A)
```

`A = 0xA5A5A5A5A5A5A5A5` is a fixed public mask. Unlike v0.1,
`Z XOR C` is not used as the next state, so the state does not algebraically
collapse to the plaintext block.

### Custom tag input

The tag is a v0.2 block-cipher CBC-MAC with a separate domain-separated key
schedule and this authenticated input:

```text
"context" || nonce || len(aad) || len(ciphertext) || aad || ciphertext
```

The context is `RIAK2CUSTOM-v02\0`, lengths are little-endian u64, and the
whole input is zero-padded only after its exact length has been included.
`RiakV2Cipher::open` verifies the tag in constant-time comparison before
returning plaintext. The current API is one-shot (`&[u8]` in/out); the CLI
reads complete files into memory. Nonce generation/reuse policy remains the
caller's responsibility.

This wrapper fixes the v0.1 mode-state and nonce-authentication bugs, but its
security still depends on the unvalidated v0.2 block cipher and requires a
full cryptanalysis review.

## CLI format

`v2enc` writes:

```text
magic "RIAK2C" || nonce(12) || ciphertext || custom tag(16)
```

The header (`magic || nonce`) is passed as AAD. `v2dec` rejects a wrong magic,
wrong key, modified header, modified ciphertext, or modified tag.

Any future F, mode, or MAC change invalidates all dependent vectors and
requires the complete analysis pipeline to be rerun.
