# RIAK

A self-designed 128-bit block cipher with a 512-bit key, written in Rust.
Full design philosophy and specification live in `krip.md` (Indonesian).

> ⚠️ **EXPERIMENTAL / BROKEN.** The v0.1 round function has a known
> deterministic linear break. v0.2 remains unvalidated and is rejected for
> production; no deterministic v0.2 outer invariant is claimed. The v0.3
> full-diffusion candidate is not validated either. Do NOT use RIAK to
> protect real or sensitive data. For real security, use an audited library
> (AES-GCM,
> ChaCha20-Poly1305).

## Structure

- **Block cipher** — 128-bit block, 512-bit key, 24 rounds, 4-branch
  Feistel (SM4-style)
- **Round function F** — ARX + multiplication by an odd constant;
  fully constant-time (no branches, no S-boxes, no data-dependent lookups)
- **Key schedule** — history-dependent 16-word state with prime round constants
  and a fixed nonlinear round-key extraction
- **Legacy "Racik" mode** — the v0.1 implementation has a documented
  plaintext-feedback/ciphertext-absorption bug; v0.1 must not be used
- **MAC** — CBC-MAC with a length block (experiment-grade integrity)

## Experimental v0.2 candidate (rejected)

The original `Riak` API above is preserved as v0.1 and marked deprecated
because of the known break. The isolated `riak::v2::RiakV2` candidate remains
available for reproducible research, but it has not passed the complete
security gates and is rejected for production use. An earlier draft claimed
an incorrect unconditional outer invariant; that claim was falsified by a
direct implementation check and is not used as evidence. The specification and
screening record remain in `docs/riak_v2.md` and
`docs/riak_v2_analysis.md`; the old vectors and CLI are retained rather than
silently overwritten.

## Experimental v0.3 candidate

`riak::v3::RiakV3` replaces the sparse outer network with four sequential
full-diffusion sub-updates per round. `riak::v3::RiakV3Cipher` and the
`v3enc`/`v3dec` commands are isolated research interfaces. v0.3 is still
**experimental**: it has passed implementation/vector checks, exact
reduced-width DDT/LAT and trail-activity screens, and an empirical mode/tag
screen, but not the full-width differential, linear-hull, boomerang,
related-key, side-channel, formal mode/tag, or external-review gates.

There are no runtime cryptography dependencies; the cipher, mode, and tag code
are implemented in this repository. The independent v0.3 reference is
`simulator/riak_v3.py`, with vectors in `tests/v3_vectors.rs` and
`tests/v3_cipher_vectors.rs`. The design and open gates are recorded in
`docs/riak_v3.md` and `docs/riak_v3_analysis.md`; the exact differential and
linear screens are in `docs/riak_v3_ddt_lat.md` with the tool under
`analysis/ddt-probe/`, and the wrapper screen is in
`docs/riak_v3_mode_analysis.md`. Independent reviewers
should start with `docs/external_review_packet.md`. Key-handling and private
reporting guidance is in `SECURITY.md`.

## Usage

Library:

```rust
use riak::Riak;

let cipher = Riak::new(&key_bytes);          // 64-byte key
let ct = cipher.encrypt(&nonce, &plaintext); // 12-byte nonce
let pt = cipher.decrypt(&nonce, &ct);
let tag = cipher.mac(&ct);
assert!(cipher.verify_mac(&ct, &tag));
```

CLI:

```text
cargo build --release
./target/release/riak keygen > key.hex
chmod 600 key.hex
./target/release/riak v3enc in.txt out.riak3c --key-file key.hex
./target/release/riak v3dec out.riak3c in.txt  --key-file key.hex
```

Raw `--key` arguments are rejected so keys do not enter the process list.
The broken v0.1 format is quarantined behind an opt-in Cargo feature and
explicit research commands:

```text
cargo build --release --features legacy-v1
./target/release/riak legacy-enc in.txt out.riak --key-file key.hex
./target/release/riak legacy-dec out.riak in.txt  --key-file key.hex
```

Without that feature, `legacy-enc`, `legacy-dec`, and the old `enc`/`dec` aliases
are unavailable. Experimental v0.2 commands remain separate:

```text
./target/release/riak v2enc in.txt out.riak2c --key-file key.hex
./target/release/riak v2dec out.riak2c in.txt  --key-file key.hex
```

`RIAK2C` and `RIAK3C` are `magic(6) || nonce(12) || ciphertext || custom
tag(16)`. The header is authenticated as AAD. On Unix, `--key-file` must be
mode `0600` or stricter, and the file is checked and read through one open
file descriptor. CLI input is limited to 64 MiB. The v0.3 library equivalent
is:

```rust
use riak::v3::RiakV3Cipher;

let cipher = RiakV3Cipher::new(&key_bytes);
let sealed = cipher.seal(&nonce, b"RIAK3C", plaintext)?;
let opened = cipher.open(&nonce, b"RIAK3C", &sealed)?;
```

For multiple messages under one key, prefer the stateful
`seal_with_sequence` API with `riak::NonceSequence`; persist a unique prefix
per key and never restart its counter with the same prefix.

Both experimental formats remain unaudited. `RIAK3C` is the current research
candidate, not a production replacement.

File format: magic `RIAK1` ‖ nonce (12 B) ‖ framed MAC tag (16 B) ‖ ciphertext.
The legacy tag binds the magic, nonce, and ciphertext length; the v0.1 block
cipher itself remains broken and is not suitable for real data.

## Testing

- `scripts/ci.sh` — local check suite (build, tests, Python reference, v2 probes)
- `cargo test --features legacy-v1 --test cli_legacy` — explicit broken-v0.1
  quarantine and framed-header regression test
- `cargo test` — unit tests + legacy vectors + 12 v0.2 and 12 v0.3 block
  vectors + 3 v0.2 and 4 v0.3 wrapper vectors + 128 generated v0.3 wrapper
  cross-check cases + v0.3 mode-audit cases,
  cross-validated against independent Python references where applicable
- `cargo run --release --example stats` — monobit / block-frequency /
  runs tests on the keystream (all pass)
- `cargo run --release --example differential` — empirical differential
  cryptanalysis (no exploitable characteristic found above 2^-20,
  including round-reduced 4-round versions)
- `cargo run --release --example linear` — legacy v0.1 probe; it now uses
  true 128-bit masks and explicitly regression-tests the known linear break
- `cargo run --release --example ddt` / `ddt_focus` — DDT probe of the
  round function F; found real differentials with DP up to 2^-11
  (documented in krip.md as open finding #1 — multi-round trail search
  is the required follow-up)
- `cargo run --release --example bench` — throughput vs AES-256 and
  ChaCha20 (4-way interleaved blocks: 658 MiB/s, 2.4x single)
- `python3 simulator/riak_v2.py` — independent v0.2 reference self-test
- `cargo run --release --example v2_probe` / `v2_ddt` — initial v0.2
  structural and empirical probes (not security proofs)
- `cargo run --release --example v2_bench` — v0.2 block/seal/open smoke benchmark
- `cargo run --release --example v2_differential` — full-block differential screen
- `cargo run --release --example v2_full_linear` — full-block structured linear screen
- `cargo run --release --example v2_related` — initial related-key smoke probe
- `cargo run --release --example v2_trail_search` — measured differential-trail search
- `python3 simulator/riak_v3.py` — independent v0.3 reference self-test
- `cargo run --release --example v3_sample -- wildanelis` — ephemeral labeled
  v0.3 sample; no key is embedded or printed
- `cargo run --release --example v3_probe` — v0.3 structural/differential/linear probe
- `cargo run --release --example v3_avalanche` — v0.3 plaintext/key diffusion smoke screen
- `cargo run --release --example v3_differential` — v0.3 full-block differential screen
- `cargo run --release --example v3_linear_trail_search` — bounded v0.3 linear-trail search
- `cargo run --release --example v3_linear_hull` — bounded v0.3 signed linear-hull screen
- `cargo run --release --example v3_full_linear` — true-vector v0.3 linear screen
- `cargo run --release --example v3_trail_search` — bounded v0.3 differential-trail search
- `cargo run --release --example v3_related` — v0.3 related-key smoke probe
- `cargo run --release --example v3_key_schedule_analysis` — v0.3 schedule/domain/linear screen
- `cargo run --release --example v3_related_multibit` — structured multi-bit/domain related-key screen
- `cargo run --release --example v3_bench` — v0.3 block/wrapper benchmark
- `cargo run --release --example v3_timing` — rough timing smoke test (not a proof)

## Status

See `krip.md` for the full roadmap: DDT analysis of F, linear
cryptanalysis, full TestU01/Dieharder battery, reference implementations
of AES/ChaCha20 for comparison, and external review.

## License

Proprietary. All rights reserved. No distribution, use, or
modification without written permission from the project owner.
