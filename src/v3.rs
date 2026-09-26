//! RIAK v0.3 candidate block cipher.
//!
//! v0.2 used a sparse four-branch shift/update. v0.3 replaces that outer
//! network with a sequential full-diffusion permutation: every output branch
//! is updated from already updated branches. v0.2 is not claimed to have a
//! deterministic outer invariant; it remains unvalidated.
//!
//! The key schedule uses a full sixteen-word nonlinear sweep followed by a
//! fixed sixteen-step nonlinear round-key extraction. Earlier sparse and
//! four-word-XOR extraction schedules were rejected after related-key screens.
//!
//! This module remains experimental. It is not a security claim.

#![forbid(unsafe_code)]

use crate::v2::{round_function, PRIMES};

/// Candidate version identifier.
pub const VERSION: &str = "0.3-candidate-r2";

/// Number of outer rounds.
pub const ROUNDS: usize = 24;

/// Default domain for the standalone block-cipher API.
pub const DOMAIN_DEFAULT: u32 = 0;

/// Domain separator for the experimental v0.3 confidentiality mode.
pub const DOMAIN_RACIK: u32 = 0x5241_4349; // "RACI"

/// Domain separator for the experimental v0.3 authentication mode.
pub const DOMAIN_MAC: u32 = 0x4D41_4349; // "MACI"

/// Public slot constants used to distinguish the four F calls in a round.
const SLOT_CONSTANTS: [u32; 4] = [
    0x0000_0000,
    0x1357_9BDF,
    0x2468_ACE0,
    0xFEDC_BA98,
];
const EXTRACTION_SEED: u32 = 0x9E37_79B9;
const EXTRACTION_TAG: u32 = 0x1357_9BDF;

#[inline(always)]
fn round_constant(round: usize, slot: usize) -> u32 {
    PRIMES[round] ^ SLOT_CONSTANTS[slot]
}

#[inline(always)]
fn extract_round_key(state: &[u32; 16], domain: u32, round: usize) -> u32 {
    // A full nonlinear extraction is intended to prevent an even XOR-linear
    // key difference from cancelling at the round-key boundary after the sweep.
    let mut accumulator = domain ^ PRIMES[round].wrapping_mul(EXTRACTION_SEED);
    for index in 0..16usize {
        let step = (index as u32).wrapping_mul(0x0100_0193);
        let constant = PRIMES[round]
            ^ SLOT_CONSTANTS[index & 3]
            ^ step
            ^ EXTRACTION_TAG;
        accumulator = round_function(
            accumulator ^ state[index],
            domain ^ step,
            constant,
        );
    }
    accumulator
}

#[inline(always)]
fn encrypt_round(block: &mut [u32; 4], key: u32, round: usize) {
    let x0 = block[0];
    let x1 = block[1];
    let x2 = block[2];
    let x3 = block[3];
    let y0 = x0
        ^ round_function(x1 ^ x2 ^ x3, key, round_constant(round, 0));
    let y1 = x1
        ^ round_function(y0 ^ x2 ^ x3, key, round_constant(round, 1));
    let y2 = x2
        ^ round_function(y1 ^ y0 ^ x3, key, round_constant(round, 2));
    let y3 = x3
        ^ round_function(y2 ^ y1 ^ y0, key, round_constant(round, 3));
    *block = [y0, y1, y2, y3];
}

/// RIAK v0.3 candidate: 128-bit block, 512-bit key, 24 rounds.
pub struct RiakV3 {
    round_keys: [u32; ROUNDS],
}

impl Drop for RiakV3 {
    fn drop(&mut self) {
        for round_key in &mut self.round_keys {
            *round_key = 0;
            std::hint::black_box(*round_key);
        }
    }
}

impl RiakV3 {
    /// Construct from a 512-bit big-endian key.
    pub fn new(key: &[u8; 64]) -> Self {
        let mut words = [0u32; 16];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_be_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        let cipher = Self::from_words(words);
        clear_words(&mut words);
        cipher
    }

    /// Construct from sixteen key words.
    pub fn from_words(key: [u32; 16]) -> Self {
        Self::from_words_with_domain(key, DOMAIN_DEFAULT)
    }

    /// Construct with a public key-schedule domain.
    pub fn from_words_with_domain(key: [u32; 16], domain: u32) -> Self {
        Self {
            round_keys: key_schedule(key, domain),
        }
    }

    /// Encrypt one block using the full-diffusion outer permutation.
    pub fn encrypt_block(&self, block: &mut [u32; 4]) {
        for round in 0..ROUNDS {
            encrypt_round(block, self.round_keys[round], round);
        }
    }

    /// Decrypt one block by reversing the four sequential updates.
    pub fn decrypt_block(&self, block: &mut [u32; 4]) {
        for round in (0..ROUNDS).rev() {
            let key = self.round_keys[round];
            let y0 = block[0];
            let y1 = block[1];
            let y2 = block[2];
            let y3 = block[3];

            let x3 = y3
                ^ round_function(y2 ^ y1 ^ y0, key, round_constant(round, 3));
            let x2 = y2
                ^ round_function(y1 ^ y0 ^ x3, key, round_constant(round, 2));
            let x1 = y1
                ^ round_function(y0 ^ x2 ^ x3, key, round_constant(round, 1));
            let x0 = y0
                ^ round_function(x1 ^ x2 ^ x3, key, round_constant(round, 0));
            *block = [x0, x1, x2, x3];
        }
    }

    /// Encrypt a reduced number of rounds for analysis.
    #[doc(hidden)]
    pub fn encrypt_block_rounds(&self, block: &mut [u32; 4], rounds: usize) {
        assert!(rounds <= ROUNDS, "round count exceeds v0.3 maximum");
        for round in 0..rounds {
            let key = self.round_keys[round];
            let x0 = block[0];
            let x1 = block[1];
            let x2 = block[2];
            let x3 = block[3];
            let y0 = x0
                ^ round_function(x1 ^ x2 ^ x3, key, round_constant(round, 0));
            let y1 = x1
                ^ round_function(y0 ^ x2 ^ x3, key, round_constant(round, 1));
            let y2 = x2
                ^ round_function(y1 ^ y0 ^ x3, key, round_constant(round, 2));
            let y3 = x3
                ^ round_function(y2 ^ y1 ^ y0, key, round_constant(round, 3));
            *block = [y0, y1, y2, y3];
        }
    }

    /// Decrypt a reduced number of rounds for analysis.
    #[doc(hidden)]
    pub fn decrypt_block_rounds(&self, block: &mut [u32; 4], rounds: usize) {
        assert!(rounds <= ROUNDS, "round count exceeds v0.3 maximum");
        for round in (0..rounds).rev() {
            let key = self.round_keys[round];
            let y0 = block[0];
            let y1 = block[1];
            let y2 = block[2];
            let y3 = block[3];
            let x3 = y3
                ^ round_function(y2 ^ y1 ^ y0, key, round_constant(round, 3));
            let x2 = y2
                ^ round_function(y1 ^ y0 ^ x3, key, round_constant(round, 2));
            let x1 = y1
                ^ round_function(y0 ^ x2 ^ x3, key, round_constant(round, 1));
            let x0 = y0
                ^ round_function(x1 ^ x2 ^ x3, key, round_constant(round, 0));
            *block = [x0, x1, x2, x3];
        }
    }

    /// Encrypt four independent blocks with interleaved rounds.
    ///
    /// The four lanes are explicitly unrolled to expose instruction-level
    /// parallelism while retaining the same fixed-round, branch-free core.
    pub fn encrypt_block_x4(&self, blocks: &mut [[u32; 4]; 4]) {
        for round in 0..ROUNDS {
            let key = self.round_keys[round];
            encrypt_round(&mut blocks[0], key, round);
            encrypt_round(&mut blocks[1], key, round);
            encrypt_round(&mut blocks[2], key, round);
            encrypt_round(&mut blocks[3], key, round);
        }
    }
}

fn clear_words(words: &mut [u32; 16]) {
    for word in words {
        *word = 0;
        std::hint::black_box(*word);
    }
}

fn key_schedule(mut key: [u32; 16], domain: u32) -> [u32; ROUNDS] {
    let mut state = key;
    let mut round_keys = [0u32; ROUNDS];
    for round in 0..ROUNDS {
        // Sweep all sixteen words. The previous sparse and four-word-XOR
        // extraction schedules left related-key differences unchanged in
        // early round keys.
        for index in 0..16usize {
            let a = state[(index + 3) & 15];
            let b = state[(index + 7) & 15].rotate_left(11);
            let c = state[(index + 13) & 15].rotate_left(5);
            let mut mixed = a ^ b ^ c;
            let step_constant = (index as u32).wrapping_mul(0x0100_0193);
            let constant = PRIMES[round]
                ^ SLOT_CONSTANTS[index & 3]
                ^ step_constant;
            mixed = round_function(mixed, domain, constant);
            state[index] ^= mixed;
        }
        round_keys[round] = extract_round_key(&state, domain, round);
    }
    clear_words(&mut key);
    clear_words(&mut state);
    round_keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn block_roundtrip() {
        let cipher = RiakV3::from_words([0x1020_3040; 16]);
        let original = [0x0123_4567, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210];
        let mut block = original;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, original);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    #[test]
    fn reduced_round_roundtrip() {
        let cipher = RiakV3::from_words([7; 16]);
        let original = [1, 2, 3, 4];
        let mut block = original;
        cipher.encrypt_block_rounds(&mut block, 4);
        cipher.decrypt_block_rounds(&mut block, 4);
        assert_eq!(block, original);
    }

    #[test]
    fn round_keys_are_distinct_for_representative_keys() {
        for key in [[0u32; 16], [0xffff_ffff; 16], [0xa5a5_a5a5; 16]] {
            let cipher = RiakV3::from_words(key);
            let unique: HashSet<_> = cipher.round_keys.iter().copied().collect();
            assert_eq!(unique.len(), ROUNDS);
        }
    }

    #[test]
    fn one_round_updates_all_branches_for_single_bit_inputs() {
        let cipher = RiakV3::from_words([0x1020_3040; 16]);
        for branch in 0..4usize {
            for bit in 0..32u32 {
                let original = [0x1234_5678, 0x90ab_cdef, 0xfedc_ba98, 0x7654_3210];
                let mut changed = original;
                changed[branch] ^= 1u32 << bit;
                let mut first = original;
                let mut second = changed;
                cipher.encrypt_block_rounds(&mut first, 1);
                cipher.encrypt_block_rounds(&mut second, 1);
                assert!(
                    first.iter().zip(second.iter()).all(|(a, b)| a != b),
                    "one-bit input did not diffuse across all branches"
                );
            }
        }
    }

    #[test]
    fn key_schedule_domains_are_separated() {
        let key = [0x1234_5678; 16];
        let mut first = [1, 2, 3, 4];
        let mut second = first;
        RiakV3::from_words_with_domain(key, DOMAIN_DEFAULT).encrypt_block(&mut first);
        RiakV3::from_words_with_domain(key, DOMAIN_RACIK).encrypt_block(&mut second);
        assert_ne!(first, second);
    }
    #[test]
    fn one_bit_key_changes_reach_every_round_key_in_screen() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state ^= state << 7;
            state ^= state >> 9;
            state
        };
        for _ in 0..256 {
            let key: [u32; 16] = std::array::from_fn(|_| next() as u32);
            let mut changed = key;
            changed[(next() as usize) % 16] ^= 1u32 << (next() % 32);
            let first = RiakV3::from_words(key);
            let second = RiakV3::from_words(changed);
            for round in 0..ROUNDS {
                assert_ne!(
                    first.round_keys[round], second.round_keys[round],
                    "one-bit key difference vanished at round {round}"
                );
            }
        }
    }
    #[test]
    fn all_ones_cross_word_differences_do_not_cancel_round_keys() {
        // All word pairs are checked because the earlier four-word XOR
        // extraction had exact cancellation for several pair families. Keep
        // this broad regression for the nonlinear full-state extraction.
        let bases: [[u32; 16]; 3] = [
            [0; 16],
            [
                0x8c09_6f85,
                0x9273_9e1d,
                0x0fab_73c8,
                0x33c9_ed71,
                0x142e_1fda,
                0x2222_fd06,
                0x94a0_017f,
                0xb868_067b,
                0xa5cc_28af,
                0x2105_2043,
                0xa60b_8e50,
                0x824d_985b,
                0x9f54_1a22,
                0xbeec_9cdc,
                0xbc5f_d612,
                0x86ec_98dd,
            ],
            [
                0xeaf2_c812,
                0xaf75_1530,
                0x640b_10d2,
                0x15b3_f492,
                0x1003_eb02,
                0x17fb_617e,
                0xccb7_455c,
                0x7374_b193,
                0x16d2_bee9,
                0x61bf_ee9b,
                0x0255_3c92,
                0x5878_7e78,
                0x68c2_cd24,
                0x1fa8_4222,
                0x86a4_e79c,
                0x3a2f_4267,
            ],
        ];
        for base in bases {
            for left in 0..16usize {
                for right in left + 1..16usize {
                    let mut related = base;
                    related[left] ^= u32::MAX;
                    related[right] ^= u32::MAX;
                    let first = RiakV3::from_words(base);
                    let second = RiakV3::from_words(related);
                    for round in 0..ROUNDS {
                        assert_ne!(
                            first.round_keys[round], second.round_keys[round],
                            "all-ones related-key difference cancelled at round {round}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn x4_matches_single_blocks() {
        let cipher = RiakV3::from_words([23; 16]);
        let mut singles: Vec<[u32; 4]> = (0..4)
            .map(|i| [i, i + 9, i + 77, i * 3 + 1])
            .collect();
        let mut quad: [[u32; 4]; 4] = std::array::from_fn(|i| {
            [i as u32, i as u32 + 9, i as u32 + 77, i as u32 * 3 + 1]
        });
        for block in &mut singles {
            cipher.encrypt_block(block);
        }
        cipher.encrypt_block_x4(&mut quad);
        assert_eq!(singles, quad);
    }
}

const MODE_ABSORB_MASK: u32 = 0xA5A5_A5A5;
const MODE_IV_MARKER: u32 = 0x5249_4333; // "RIC3"
const MAC_CONTEXT: [u8; 16] = *b"RIAK3CUSTOM-v03\0";

/// Size of the experimental v0.3 authentication tag.
pub const AUTH_TAG_LEN: usize = 16;

/// Maximum message size accepted by the wrapper.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// Errors returned by the experimental v0.3 wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3Error {
    /// The authentication tag did not verify.
    AuthenticationFailed,
    /// The input would require more than 2^32 counter blocks.
    CounterOverflow,
    /// A length cannot be represented by the format.
    LengthOverflow,
}

impl std::fmt::Display for V3Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::CounterOverflow => formatter.write_str("counter block limit exceeded"),
            Self::LengthOverflow => formatter.write_str("length cannot be represented"),
        }
    }
}

impl std::error::Error for V3Error {}

fn check_lengths(aad_len: usize, data_len: usize) -> Result<(), V3Error> {
    let overhead = MAC_CONTEXT.len() + 12 + 8 + 8;
    let total = aad_len
        .checked_add(data_len)
        .and_then(|value| value.checked_add(overhead))
        .ok_or(V3Error::LengthOverflow)?;
    if aad_len > MAX_MESSAGE_SIZE || data_len > MAX_MESSAGE_SIZE || total > MAX_MESSAGE_SIZE + 64 {
        return Err(V3Error::LengthOverflow);
    }
    Ok(())
}

/// Experimental custom confidentiality/authentication wrapper around v0.3.
///
/// This is not a standardized AEAD and is not externally audited. The caller
/// must never reuse a nonce with the same master key.
pub struct RiakV3Cipher {
    enc: RiakV3,
    mac: RiakV3,
}

impl RiakV3Cipher {
    /// Construct the wrapper from a 512-bit big-endian master key.
    pub fn new(key: &[u8; 64]) -> Self {
        let mut words = [0u32; 16];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_be_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        let cipher = Self::from_words(words);
        clear_words(&mut words);
        cipher
    }

    /// Construct the wrapper from sixteen key words.
    pub fn from_words(mut key: [u32; 16]) -> Self {
        let enc = RiakV3::from_words_with_domain(key, DOMAIN_RACIK);
        let mac = RiakV3::from_words_with_domain(key, DOMAIN_MAC);
        clear_words(&mut key);
        Self { enc, mac }
    }

    /// Encrypt and authenticate a message, returning `ciphertext || tag`.
    pub fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, V3Error> {
        check_lengths(aad.len(), plaintext.len())?;
        let ciphertext = self.racik(nonce, plaintext, false)?;
        let tag = self.auth_tag(nonce, aad, &ciphertext)?;
        let capacity = ciphertext
            .len()
            .checked_add(AUTH_TAG_LEN)
            .ok_or(V3Error::LengthOverflow)?;
        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&tag);
        Ok(output)
    }

    /// Verify the tag before decrypting or returning any plaintext.
    pub fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, V3Error> {
        if sealed.len() < AUTH_TAG_LEN {
            return Err(V3Error::AuthenticationFailed);
        }
        if sealed.len() > MAX_MESSAGE_SIZE + AUTH_TAG_LEN || aad.len() > MAX_MESSAGE_SIZE {
            return Err(V3Error::LengthOverflow);
        }
        let ciphertext_len = sealed.len() - AUTH_TAG_LEN;
        let (ciphertext, tag_bytes) = sealed.split_at(ciphertext_len);
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(tag_bytes);
        let expected = self.auth_tag(nonce, aad, ciphertext)?;
        if !constant_time_equal(&tag, &expected) {
            return Err(V3Error::AuthenticationFailed);
        }
        self.racik(nonce, ciphertext, true)
    }

    fn racik(
        &self,
        nonce: &[u8; 12],
        data: &[u8],
        decrypt: bool,
    ) -> Result<Vec<u8>, V3Error> {
        let block_count = data
            .len()
            .checked_add(15)
            .ok_or(V3Error::LengthOverflow)?
            / 16;
        if block_count > u32::MAX as usize {
            return Err(V3Error::CounterOverflow);
        }

        let mut state = self.mode_initial_state(nonce);
        let mut output = vec![0u8; data.len()];
        for (index, (input, output_block)) in data
            .chunks(16)
            .zip(output.chunks_mut(16))
            .enumerate()
        {
            let mut counter = state;
            counter[0] = counter[0].wrapping_add(index as u32);
            let mut keystream = counter;
            self.enc.encrypt_block(&mut keystream);

            for (j, &byte) in input.iter().enumerate() {
                let stream_byte = (keystream[j / 4] >> (24 - 8 * (j % 4))) as u8;
                output_block[j] = byte ^ stream_byte;
            }

            // The next state binds both the previous state and the absorbed
            // ciphertext, avoiding the v0.1 Z XOR C = P collapse.
            let mut next = [0u32; 4];
            let absorb_source = if decrypt { input } else { output_block };
            for (j, &byte) in absorb_source.iter().enumerate() {
                next[j / 4] |= (u32::from(byte)) << (24 - 8 * (j % 4));
            }
            for word in &mut next {
                *word ^= MODE_ABSORB_MASK;
            }
            for j in 0..4 {
                next[j] ^= state[j];
            }
            self.enc.encrypt_block(&mut next);
            state = next;
        }
        Ok(output)
    }

    fn mode_initial_state(&self, nonce: &[u8; 12]) -> [u32; 4] {
        let mut state = [0u32; 4];
        for i in 0..3 {
            state[i] = u32::from_be_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        state[3] = MODE_IV_MARKER;
        self.enc.encrypt_block(&mut state);
        state
    }

    fn auth_tag(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<[u8; AUTH_TAG_LEN], V3Error> {
        check_lengths(aad.len(), ciphertext.len())?;
        let aad_len = u64::try_from(aad.len()).map_err(|_| V3Error::LengthOverflow)?;
        let ciphertext_len =
            u64::try_from(ciphertext.len()).map_err(|_| V3Error::LengthOverflow)?;
        let mut input = Vec::new();
        input.extend_from_slice(&MAC_CONTEXT);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&aad_len.to_le_bytes());
        input.extend_from_slice(&ciphertext_len.to_le_bytes());
        input.extend_from_slice(aad);
        input.extend_from_slice(ciphertext);

        let total_len = u64::try_from(input.len()).map_err(|_| V3Error::LengthOverflow)?;
        let mut chain = [0u32; 4];
        chain[2] = (total_len >> 32) as u32;
        chain[3] = total_len as u32;
        self.mac.encrypt_block(&mut chain);
        for chunk in input.chunks(16) {
            let mut block = [0u32; 4];
            for (j, &byte) in chunk.iter().enumerate() {
                block[j / 4] |= (u32::from(byte)) << (24 - 8 * (j % 4));
            }
            for j in 0..4 {
                chain[j] ^= block[j];
            }
            self.mac.encrypt_block(&mut chain);
        }

        let mut tag = [0u8; AUTH_TAG_LEN];
        for (i, word) in chain.iter().enumerate() {
            tag[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        Ok(tag)
    }
}

fn constant_time_equal(a: &[u8; AUTH_TAG_LEN], b: &[u8; AUTH_TAG_LEN]) -> bool {
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod wrapper_tests {
    use super::*;

    #[test]
    fn length_limit_rejects_oversized_input_without_allocating() {
        assert_eq!(
            check_lengths(MAX_MESSAGE_SIZE + 1, 0),
            Err(V3Error::LengthOverflow)
        );
        assert_eq!(
            check_lengths(0, MAX_MESSAGE_SIZE + 1),
            Err(V3Error::LengthOverflow)
        );
    }

    #[test]
    fn custom_seal_open_roundtrip() {
        let cipher = RiakV3Cipher::from_words([0x1357_9bdf; 16]);
        let nonce = [0x42u8; 12];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 257] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let sealed = cipher.seal(&nonce, b"RIAK3C", &plaintext).unwrap();
            assert_eq!(sealed.len(), plaintext.len() + AUTH_TAG_LEN);
            assert_eq!(cipher.open(&nonce, b"RIAK3C", &sealed).unwrap(), plaintext);
        }
    }

    #[test]
    fn custom_open_rejects_tampering_and_wrong_context() {
        let cipher = RiakV3Cipher::from_words([0x0102_0304; 16]);
        let nonce = [0x99u8; 12];
        let sealed = cipher.seal(&nonce, b"aad", b"message").unwrap();
        assert!(cipher.open(&nonce, b"aad", &sealed).is_ok());
        assert!(cipher.open(&nonce, b"bad", &sealed).is_err());
        let mut changed = sealed.clone();
        changed[0] ^= 1;
        assert!(cipher.open(&nonce, b"aad", &changed).is_err());
        assert!(cipher.open(&[0u8; 12], b"aad", &sealed).is_err());
    }
}
