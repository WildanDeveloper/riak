//! RIAK — self-designed block cipher.
//!
//! Full specification: see `krip.md`, section "Spek Matematis v0.1".
//!
//! ⚠️ EXPERIMENTAL / BROKEN. The v0.1 round function has a known
//! deterministic linear break. v0.2 remains unvalidated and is rejected for
//! production; no deterministic v0.2 outer invariant is claimed. The v0.3
//! candidate is unaudited. Do NOT use this crate to
//! protect real data.
//!
//! Legacy v0.1 structure:
//! - 128-bit block cipher, 512-bit key, 24 rounds, 4-branch Feistel (SM4-style)
//! - Round function F: ARX + multiplication by an odd constant
//!   (fully constant-time, no S-boxes)
//! - Key schedule: history-dependent expansion with prime constants
//! - "Racik" mode: CTR variant with ciphertext-absorbing chaining
//!
//! The isolated v0.3 module replaces the rejected v0.2 outer network and uses
//! a full-diffusion sequential network; see `docs/riak_v3.md`.

#![forbid(unsafe_code)]
#![allow(deprecated)]

/// Rejected RIAK v0.2 candidate retained for reproducible research.
pub mod v2;

/// Experimental RIAK v0.3 candidate with a full-diffusion outer network.
pub mod v3;

/// Nonce generation helpers for stateful encryption.
pub mod nonce;

pub use nonce::{NonceError, NonceSequence};

pub const ROUNDS: usize = 24;

/// Primes as round constants (see krip.md: their role is only
/// "unremarkable public constants", not a source of security).
pub const PRIMES: [u32; 36] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151,
];

/// Golden-ratio constant (odd → multiplication is always bijective mod 2^32).
const MUL: u32 = 0x9E37_79B9;

/// Domain separation for the framed legacy MAC.
const LEGACY_MAC_CONTEXT: &[u8] = b"RIAK1-FRAMED\0\0\0\0";

/// Round function F (32-bit → 32-bit), fully constant-time:
/// xor key → add constant → multiply constant → rotation interference.
#[inline(always)]
fn f(x: u32, k: u32, c: u32) -> u32 {
    let mut t = x ^ k;
    t = t.wrapping_add(c);
    t = t.wrapping_mul(MUL);
    t ^= t.rotate_left(9);
    t ^= t.rotate_left(17);
    t ^= t.rotate_left(23);
    t
}

/// RIAK block cipher: 128-bit block, 512-bit key, 24 rounds.
///
/// **Broken legacy primitive.** v0.2 is also rejected because of its outer
/// invariant; v0.3 is only an unaudited research candidate.
#[deprecated(note = "RIAK v0.1 has a known deterministic linear break; v0.2 is also rejected; v0.3 is unaudited")]
#[derive(Clone)]
pub struct Riak {
    rk: [u32; ROUNDS],
}

impl Drop for Riak {
    fn drop(&mut self) {
        for round_key in &mut self.rk {
            *round_key = 0;
            std::hint::black_box(*round_key);
        }
    }
}

impl Riak {
    /// Build the cipher from a 512-bit key (64 bytes, big-endian per word).
    pub fn new(key: &[u8; 64]) -> Self {
        let mut kw = [0u32; 16];
        for (i, w) in kw.iter_mut().enumerate() {
            *w = u32::from_be_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        let cipher = Self::from_words(kw);
        clear_words(&mut kw);
        cipher
    }

    /// Build the cipher from the key as 16 u32 words.
    pub fn from_words(mut key: [u32; 16]) -> Self {
        let round_keys = key_schedule(key);
        clear_words(&mut key);
        Self { rk: round_keys }
    }

    /// Encrypt one 128-bit block (4 words, in place).
    pub fn encrypt_block(&self, w: &mut [u32; 4]) {
        for r in 0..ROUNDS {
            let nxt = w[0]
                ^ f(
                    w[1] ^ w[2] ^ w[3],
                    self.rk[r],
                    PRIMES[r],
                );
            *w = [w[1], w[2], w[3], nxt];
        }
    }

    /// Encrypt one block with a reduced round count — analysis tool
    /// (differential cryptanalysis on round-reduced versions).
    #[doc(hidden)]
    pub fn encrypt_block_rounds(&self, w: &mut [u32; 4], rounds: usize) {
        assert!(rounds <= ROUNDS, "round count exceeds RIAK maximum");
        for r in 0..rounds {
            let nxt = w[0] ^ f(w[1] ^ w[2] ^ w[3], self.rk[r], PRIMES[r]);
            *w = [w[1], w[2], w[3], nxt];
        }
    }

    /// Encrypt 4 independent blocks in parallel (interleaved rounds).
    /// Same result as calling `encrypt_block` four times; the
    /// interleaving gives the CPU independent dependency chains to
    /// overlap, hiding the serial latency of the round chain.
    pub fn encrypt_block_x4(&self, blocks: &mut [[u32; 4]; 4]) {
        for r in 0..ROUNDS {
            let rk = self.rk[r];
            let pr = PRIMES[r];
            for b in blocks.iter_mut() {
                let nxt = b[0] ^ f(b[1] ^ b[2] ^ b[3], rk, pr);
                *b = [b[1], b[2], b[3], nxt];
            }
        }
    }

    /// Decrypt one 128-bit block (in place; exact inverse of
    /// `encrypt_block` — the Feistel structure guarantees invertibility).
    pub fn decrypt_block(&self, w: &mut [u32; 4]) {
        for r in (0..ROUNDS).rev() {
            let prev = w[3]
                ^ f(
                    w[0] ^ w[1] ^ w[2],
                    self.rk[r],
                    PRIMES[r],
                );
            *w = [prev, w[0], w[1], w[2]];
        }
    }

    /// Encrypt a buffer of arbitrary length using "Racik" mode
    /// (CTR variant with ciphertext-absorbing chaining).
    ///
    /// `nonce` is 12 bytes. The nonce MUST NOT be reused with the same
    /// key — reusing it collapses the security of every message.
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let mut s = self.initial_state(nonce);
        let mut out = vec![0u8; plaintext.len()];
        for (i, (chunk, out_chunk)) in plaintext
            .chunks(16)
            .zip(out.chunks_mut(16))
            .enumerate()
        {
            let mut counter_block = s;
            counter_block[0] = counter_block[0].wrapping_add(i as u32);
            let mut z = counter_block;
            self.encrypt_block(&mut z);
            for (j, b) in chunk.iter().enumerate() {
                out_chunk[j] = b ^ (z[j / 4] >> (24 - 8 * (j % 4))) as u8;
            }
            // Fermentation: the state absorbs the ciphertext.
            let mut c_words = [0u32; 4];
            for (j, b) in out_chunk.iter().enumerate() {
                c_words[j / 4] |= (u32::from(*b)) << (24 - 8 * (j % 4));
            }
            s = [z[0] ^ c_words[0], z[1] ^ c_words[1], z[2] ^ c_words[2], z[3] ^ c_words[3]];
        }
        out
    }

    /// Decrypt "Racik" mode. Error propagation: one corrupted ciphertext
    /// byte corrupts that block and every block after it (integrity
    /// amplifier, like CBC). This is NOT authentication.
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let mut s = self.initial_state(nonce);
        let mut out = vec![0u8; ciphertext.len()];
        for (i, (chunk, out_chunk)) in ciphertext
            .chunks(16)
            .zip(out.chunks_mut(16))
            .enumerate()
        {
            let mut counter_block = s;
            counter_block[0] = counter_block[0].wrapping_add(i as u32);
            let mut z = counter_block;
            self.encrypt_block(&mut z);
            let mut c_words = [0u32; 4];
            for (j, b) in chunk.iter().enumerate() {
                c_words[j / 4] |= (u32::from(*b)) << (24 - 8 * (j % 4));
                out_chunk[j] = b ^ (z[j / 4] >> (24 - 8 * (j % 4))) as u8;
            }
            s = [z[0] ^ c_words[0], z[1] ^ c_words[1], z[2] ^ c_words[2], z[3] ^ c_words[3]];
        }
        out
    }

    /// S₀ = E_K(nonce ‖ 0³²)
    fn initial_state(&self, nonce: &[u8; 12]) -> [u32; 4] {
        let mut block = [0u32; 4];
        for i in 0..3 {
            block[i] = u32::from_be_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        self.encrypt_block(&mut block);
        block
    }

    /// Compute a 128-bit MAC over data of arbitrary length.
    ///
    /// Construction: CBC-MAC with a length block prepended
    /// (`E_K(len) ‖ CBC-chain ‖ E_K(final)`). The length block blocks
    /// extension attacks for variable-length messages.
    ///
    /// Caveat: this is a basic experiment MAC over exactly `data`. It does
    /// not bind an external file header; use [`Self::mac_framed`] for framed
    /// formats. Full security requires an AEAD construction — future work.
    pub fn mac(&self, data: &[u8]) -> [u8; 16] {
        // Length block: 64-bit big-endian bit length, left half zeros.
        let mut chain = [0u32; 4];
        chain[2] = (data.len() as u64 >> 32) as u32;
        chain[3] = data.len() as u32;
        self.encrypt_block(&mut chain);

        for chunk in data.chunks(16) {
            let mut block = [0u32; 4];
            for (j, b) in chunk.iter().enumerate() {
                block[j / 4] |= (u32::from(*b)) << (24 - 8 * (j % 4));
            }
            for w in 0..4 {
                chain[w] ^= block[w];
            }
            self.encrypt_block(&mut chain);
        }

        let mut out = [0u8; 16];
        for (i, w) in chain.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// Compute a legacy MAC that binds a header, nonce, and ciphertext.
    ///
    /// The raw [`Self::mac`] function is retained for research vectors, but it
    /// does not authenticate a surrounding file header. Callers that persist
    /// a framed format should use this method instead.
    pub fn mac_framed(
        &self,
        header: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> [u8; 16] {
        let header_len = (header.len() as u64).to_le_bytes();
        let ciphertext_len = (ciphertext.len() as u64).to_le_bytes();
        let mut framed = Vec::with_capacity(
            LEGACY_MAC_CONTEXT.len() + 16 + header.len() + nonce.len() + ciphertext.len(),
        );
        framed.extend_from_slice(LEGACY_MAC_CONTEXT);
        framed.extend_from_slice(&header_len);
        framed.extend_from_slice(&ciphertext_len);
        framed.extend_from_slice(header);
        framed.extend_from_slice(nonce);
        framed.extend_from_slice(ciphertext);
        self.mac(&framed)
    }

    /// Verify a framed legacy MAC in constant time.
    pub fn verify_framed(
        &self,
        header: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> bool {
        let expected = self.mac_framed(header, nonce, ciphertext);
        let mut difference = 0u8;
        for (left, right) in expected.iter().zip(tag.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }

    /// Verify a MAC in constant time (no early exit on mismatch).
    pub fn verify_mac(&self, data: &[u8], tag: &[u8; 16]) -> bool {
        let expected = self.mac(data);
        let mut difference = 0u8;
        for (left, right) in expected.iter().zip(tag.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

fn clear_words(words: &mut [u32; 16]) {
    for word in words {
        *word = 0;
        std::hint::black_box(*word);
    }
}

/// Key schedule (see krip.md): a 16-word state with history-dependent
/// feedback; each round key mixes words already changed by previous
/// rounds.
fn key_schedule(mut key: [u32; 16]) -> [u32; ROUNDS] {
    let mut a = key;
    let mut rk = [0u32; ROUNDS];
    for r in 0..ROUNDS {
        let mut s = a[0] ^ a[5].rotate_left(7) ^ a[11];
        s = f(s, PRIMES[r], 0);
        a[0] ^= s;
        a.rotate_left(1);
        rk[r] = s ^ a[3] ^ a[9];
    }
    clear_words(&mut key);
    clear_words(&mut a);
    rk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_block() {
        let key = [7u32; 16];
        let c = Riak::from_words(key);
        let mut block = [0x0123_4567, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210];
        let orig = block;
        c.encrypt_block(&mut block);
        assert_ne!(block, orig);
        c.decrypt_block(&mut block);
        assert_eq!(block, orig);
    }

    #[test]
    fn roundtrip_mode_many_lengths() {
        let key = [0xA5u32; 16];
        let c = Riak::from_words(key);
        let nonce = [1u8; 12];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let ct = c.encrypt(&nonce, &pt);
            assert_eq!(ct.len(), pt.len());
            let back = c.decrypt(&nonce, &ct);
            assert_eq!(back, pt, "length {len}");
        }
    }

    #[test]
    fn different_nonce_different_ciphertext() {
        let c = Riak::from_words([9u32; 16]);
        let pt = [42u8; 32];
        let ct1 = c.encrypt(&[1u8; 12], &pt);
        let ct2 = c.encrypt(&[2u8; 12], &pt);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn weak_keys_produce_output() {
        // Not proof of no weak keys — only a smoke test.
        for kw in [[0u32; 16], [0xFFFF_FFFF; 16], [0xA5A5_A5A5; 16]] {
            let c = Riak::from_words(kw);
            let mut b = [1u32, 2, 3, 4];
            c.encrypt_block(&mut b);
            assert_ne!(b, [1, 2, 3, 4]);
        }
    }

    #[test]
    fn mac_accepts_valid_rejects_tampered() {
        let c = Riak::from_words([11u32; 16]);
        let data = b"attack at dawn";
        let tag = c.mac(data);
        assert!(c.verify_mac(data, &tag));
        assert!(!c.verify_mac(b"attack at dusk", &tag));
        let mut tampered = tag;
        tampered[0] ^= 1;
        assert!(!c.verify_mac(data, &tampered));
        // MAC is deterministic and length-sensitive (length block).
        assert_ne!(c.mac(&data[..13]), tag);
    }

    #[test]
    fn framed_mac_binds_header_and_nonce() {
        let c = Riak::from_words([0x33u32; 16]);
        let nonce = [0x44u8; 12];
        let header = b"RIAK1\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44";
        let ciphertext = b"ciphertext";
        let tag = c.mac_framed(header, &nonce, ciphertext);
        assert!(c.verify_framed(header, &nonce, ciphertext, &tag));
        let mut changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        assert!(!c.verify_framed(header, &changed_nonce, ciphertext, &tag));
        assert!(!c.verify_framed(b"RIAK2", &nonce, ciphertext, &tag));
    }

    #[test]
    fn x4_matches_single_block() {
        let c = Riak::from_words([23u32; 16]);
        let mut singles: Vec<[u32; 4]> =
            (0..4).map(|i| [i, i + 9, i + 77, i * 3 + 1]).collect();
        let mut quad: [[u32; 4]; 4] =
            std::array::from_fn(|i| [i as u32, i as u32 + 9, i as u32 + 77, i as u32 * 3 + 1]);
        for b in singles.iter_mut() {
            c.encrypt_block(b);
        }
        c.encrypt_block_x4(&mut quad);
        assert_eq!(singles, quad);
    }
}
