# RIAK v0.3 Wrapper Mode and Tag Analysis

Date: 2026-09-26

Tool: `examples/v3_mode_analysis.rs`, tests in `tests/v3_mode_audit.rs`

**This is a bounded empirical screen. No formal mode/tag security argument has
been written or machine-checked, and nothing here is a security claim.**

## Construction under review

The `RIAK3C` wrapper is encrypt-then-MAC with two separately domain-separated
instances of the same custom block cipher:

- confidentiality instance: key-schedule domain `DOMAIN_RACIK`
- authentication instance: key-schedule domain `DOMAIN_MAC`

Confidentiality state (`racik` in `src/v3.rs`), for block index `i`:

```text
state_0 = E(IV(nonce))
KS_i    = E(state_i with word 0 incremented by i)
C_i     = P_i XOR KS_i
state_{i+1} = E(pack(C_i) XOR MODE_ABSORB_MASK XOR state_i)
```

The tag input is length-prefixed and domain-tagged:

```text
MAC_CONTEXT(16) || nonce(12) || aad_len(8, LE) || ct_len(8, LE) || aad || ciphertext
```

with `total_len` seeded into the initial chaining state. The tag is verified
before any decryption and the comparison is a fixed-width XOR accumulation.

## 1. Nonce reuse remains a real confidentiality failure

```text
same key, same nonce, different messages
keystream bytes recovered identically: 64 of 64
consequence: P1 XOR P2 = C1 XOR C2 for the whole shared prefix
```

This is inherent to the construction, not a defect that documentation can
repair. For the stateless API, reusing a `(key, nonce)` pair destroys
confidentiality for the shared prefix.

Status:

- **mitigated at the API level** by `NonceSequence` / `seal_with_sequence`, which
  makes reuse inside one persisted prefix impossible and refuses to wrap;
- **not mitigated** for callers who use the raw `seal(nonce, ...)` API, who
  restore a counter from an uncertain state, or who share a prefix across keys;
- therefore v0.3 remains unsuitable for anything where nonce discipline cannot
  be guaranteed by construction.

## 2. Keystream independence across distinct nonces

4096 random nonces under one key, 32-byte keystream prefixes:

```text
distinct keystream prefixes: 4096 of 4096
equal keystream bytes over all pairs: 1048909 of 268369920
expected by chance for random streams: ~1048320
```

The measured rate is within 0.06% of the random expectation. No repeated
keystream was found. This is a screen against an obviously broken nonce
binding; it is not a PRF argument.

## 3. Ciphertext chaining, verified as a dependency rather than assumed

The keystream for block `i` depends on `C_0..C_(i-1)` and on nothing else. The
regression test isolates this by sealing two messages under one nonce (a
prohibited misuse, used here only to hold the nonce constant) that share block 0
and differ in block 1:

- block 0 plaintext identical, therefore `C_0` identical;
- **block 1 keystream identical**, and `C_1` differs by exactly the plaintext
  difference;
- block 2 plaintext byte-for-byte identical, yet **block 2 keystream diverges**,
  because `C_1` changed the chaining state.

The last point is the one that matters: divergence with identical plaintext can
only come from the chaining state, so the absorption is real and not an artefact
of the differing plaintext.

Operational consequence: a single modified ciphertext block garbles every later
plaintext block, so the mode has no random access and no resynchronisation.
Integrity comes from the tag, not from the mode. A bit flip in block 0 is
rejected before any plaintext is produced.

## 4. Confidentiality/authentication domain separation

1024 samples comparing the confidentiality keystream against the authentication
tag under the same key and nonce:

```text
identical bytes: 68 of 16384      (expected by chance: ~64)
identical 32-bit words: 0 of 4096 (expected by chance: ~0.00)
```

No shared relation between the two instances was found. Note that this measures
*output* separation. It does not measure the round-key distance between the two
domains, which is a stronger and still unmeasured property.

## 5. Length binding and truncation

The tag binds `aad_len`, `ct_len`, and `total_len` explicitly, and the
regression tests now cover:

- **every** truncation of a sealed message is rejected, not just the last block;
- ciphertext extension by a partial block and by a full block is rejected;
- an empty ciphertext is distinguishable from an absent one: sealing an empty
  message yields a 16-byte tag that differs from the tag of a one-byte message
  under the same nonce and aad.

## What is still open for the mode and tag

- **No formal security argument.** There is no written proof sketch, no
  indifferentiability or generic-bound argument, and no machine-checked model.
  Encrypt-then-MAC with a custom cipher and a custom tag is not automatically
  secure; the composition needs its own proof and the cipher underneath it is
  unaudited.
- **No forgery or indistinguishability testing.** Nothing here measures
  forgery probability, and the 128-bit tag is unanalyzed.
- **No related-key or nonce-derivation analysis of the tag.** In particular the
  interaction between the two domains under related keys is unmeasured.
- **Nonce misuse is not made safe**, only harder to trigger through the
  convenience API.
- **No full-width cryptanalysis of the underlying block cipher.** See
  `docs/riak_v3_ddt_lat.md`; the reduced-width screen found no break and the
  full-width families remain unanalyzed.

Correct one-sentence status: **the wrapper's length binding, chaining
dependency, and domain separation were measured and behave as documented, nonce
reuse is still a genuine confidentiality failure for stateless callers, and no
formal mode/tag argument exists yet.**
