//! RIAK v0.2 candidate block cipher.
//!
//! This module is a rejected research replacement for the broken v0.1 round
//! function. It deliberately lives beside v0.1 so the old implementation,
//! vectors, and cryptanalysis evidence remain reproducible.
//!
//! **Rejected for production, retained for reproducibility:** the v0.2
//! candidate has not passed the complete differential, linear-hull,
//! related-key, side-channel, and mode gates. No deterministic outer-network
//! invariant is claimed here; the module must not be used for new data.
//!
//! The candidate is **not cryptographically validated** and is not a
//! replacement for any production primitive.
//!
//! Design goals:
//! - fixed 128-bit block and 512-bit key;
//! - four-branch Feistel network;
//! - branch-free, table-free 32-bit round function;
//! - every linear mixing layer is checked to have full GF(2) rank;
//! - odd multiplications and modular additions provide nonlinear mixing.

#![forbid(unsafe_code)]

/// Candidate version identifier.
pub const VERSION: &str = "0.2-candidate";

/// Number of Feistel rounds.
pub const ROUNDS: usize = 24;

/// Default domain for the standalone block-cipher API.
pub const DOMAIN_DEFAULT: u32 = 0;

/// Domain separator for the experimental Racik confidentiality mode.
pub const DOMAIN_RACIK: u32 = 0x5241_4349; // "RACI"

/// Domain separator for the experimental authentication mode.
pub const DOMAIN_MAC: u32 = 0x4D41_4349; // "MACI"

/// Public round constants. Their pattern is not a security mechanism.
pub const PRIMES: [u32; ROUNDS] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
];

// Fixed public odd multipliers. Oddness makes each multiplication
// bijective modulo 2^32; the particular values still require cryptanalysis.
const MUL_A: u32 = 0x9E37_79B9;
const MUL_B: u32 = 0x85EB_CA6B;
const MUL_C: u32 = 0xC2B2_AE35;
const ADD_A: u32 = 0x7F4A_7C15;
const ADD_B: u32 = 0x1B87_3593;

/// First linear mixing layer.
///
/// The sequence is intentionally explicit: each assignment uses the
/// updated value, so this is a sequential xorshift/rotate network.
#[inline(always)]
fn mix_a(mut t: u32) -> u32 {
    t ^= t >> 7;
    t = t.rotate_left(11);
    t ^= t << 9;
    t
}

/// Second linear mixing layer.
#[inline(always)]
fn mix_b(mut t: u32) -> u32 {
    t ^= t >> 5;
    t = t.rotate_left(7);
    t ^= t << 13;
    t
}

/// Third linear mixing layer.
#[inline(always)]
fn mix_c(mut t: u32) -> u32 {
    t ^= t >> 17;
    t = t.rotate_left(19);
    t ^= t << 15;
    t
}

/// Candidate 32-bit round function.
///
/// All multipliers are odd and all three linear layers are full-rank over
/// GF(2), making the round function a permutation. This is a structural
/// property, not a claim of differential or linear security.
#[inline(always)]
pub fn round_function(x: u32, k: u32, c: u32) -> u32 {
    let mut t = x ^ k;
    t = t.wrapping_add(c);
    t = t.wrapping_mul(MUL_A);
    t = mix_a(t);
    t = t.wrapping_add(ADD_A);
    t = t.wrapping_mul(MUL_B);
    t = mix_b(t);
    t = t.wrapping_add(ADD_B);
    t = t.wrapping_mul(MUL_C);
    mix_c(t)
}

/// RIAK v0.2 candidate: 128-bit block, 512-bit key, 24 rounds.
pub struct RiakV2 {
    round_keys: [u32; ROUNDS],
}

impl Drop for RiakV2 {
    fn drop(&mut self) {
        // Best-effort clearing without an external dependency. `black_box`
        // discourages the optimizer from treating these writes as dead.
        for round_key in &mut self.round_keys {
            *round_key = 0;
            std::hint::black_box(*round_key);
        }
    }
}

impl RiakV2 {
    /// Construct the candidate from a 512-bit big-endian key.
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
        Self::from_words(words)
    }

    /// Construct the candidate from sixteen key words.
    pub fn from_words(key: [u32; 16]) -> Self {
        Self::from_words_with_domain(key, DOMAIN_DEFAULT)
    }

    /// Construct the candidate with a public domain separator.
    ///
    /// The domain is mixed into every key-schedule round. This is domain
    /// separation, not a proof of related-key security.
    pub fn from_words_with_domain(key: [u32; 16], domain: u32) -> Self {
        Self {
            round_keys: key_schedule(key, domain),
        }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u32; 4]) {
        for r in 0..ROUNDS {
            let next = block[0]
                ^ round_function(
                    block[1] ^ block[2] ^ block[3],
                    self.round_keys[r],
                    PRIMES[r],
                );
            *block = [block[1], block[2], block[3], next];
        }
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&self, block: &mut [u32; 4]) {
        for r in (0..ROUNDS).rev() {
            let previous = block[3]
                ^ round_function(
                    block[0] ^ block[1] ^ block[2],
                    self.round_keys[r],
                    PRIMES[r],
                );
            *block = [previous, block[0], block[1], block[2]];
        }
    }

    /// Encrypt with a reduced round count for analysis only.
    #[doc(hidden)]
    pub fn encrypt_block_rounds(&self, block: &mut [u32; 4], rounds: usize) {
        assert!(rounds <= ROUNDS, "round count exceeds v0.2 maximum");
        for r in 0..rounds {
            let next = block[0]
                ^ round_function(
                    block[1] ^ block[2] ^ block[3],
                    self.round_keys[r],
                    PRIMES[r],
                );
            *block = [block[1], block[2], block[3], next];
        }
    }

    /// Decrypt with a reduced round count for analysis only.
    #[doc(hidden)]
    pub fn decrypt_block_rounds(&self, block: &mut [u32; 4], rounds: usize) {
        assert!(rounds <= ROUNDS, "round count exceeds v0.2 maximum");
        for r in (0..rounds).rev() {
            let previous = block[3]
                ^ round_function(
                    block[0] ^ block[1] ^ block[2],
                    self.round_keys[r],
                    PRIMES[r],
                );
            *block = [previous, block[0], block[1], block[2]];
        }
    }

    /// Encrypt four independent blocks with interleaved rounds.
    pub fn encrypt_block_x4(&self, blocks: &mut [[u32; 4]; 4]) {
        for r in 0..ROUNDS {
            let round_key = self.round_keys[r];
            let round_constant = PRIMES[r];
            for block in blocks.iter_mut() {
                let next = block[0]
                    ^ round_function(
                        block[1] ^ block[2] ^ block[3],
                        round_key,
                        round_constant,
                    );
                *block = [block[1], block[2], block[3], next];
            }
        }
    }
}

/// Candidate key schedule. It retains the v0.1 history-dependent shape but
/// uses the v0.2 round function.
fn key_schedule(key: [u32; 16], domain: u32) -> [u32; ROUNDS] {
    let mut state = key;
    let mut round_keys = [0u32; ROUNDS];

    for r in 0..ROUNDS {
        let mut s = state[0] ^ state[5].rotate_left(7) ^ state[11];
        s = round_function(s, PRIMES[r], domain);
        state[0] ^= s;
        state.rotate_left(1);
        round_keys[r] = s ^ state[3] ^ state[9];
    }

    round_keys
}

/// Fixed mask used before absorbing a ciphertext block into Racik state.
const MODE_ABSORB_MASK: u32 = 0xA5A5_A5A5;

/// Initial-state marker for the experimental Racik mode.
const MODE_IV_MARKER: u32 = 0x5241_4349; // "RACI"

/// Fixed context block included in the experimental authentication input.
const MAC_CONTEXT: [u8; 16] = *b"RIAK2CUSTOM-v02\0";

/// Size of the experimental authentication tag.
pub const AUTH_TAG_LEN: usize = 16;

/// Errors returned by the experimental v0.2 confidentiality/authentication
/// wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2Error {
    /// The authentication tag did not verify.
    AuthenticationFailed,
    /// The input would require more than 2^32 counter blocks.
    CounterOverflow,
    /// A length cannot be represented by the format.
    LengthOverflow,
}

impl std::fmt::Display for V2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::CounterOverflow => formatter.write_str("counter block limit exceeded"),
            Self::LengthOverflow => formatter.write_str("length cannot be represented"),
        }
    }
}

impl std::error::Error for V2Error {}

/// Experimental custom confidentiality + authentication wrapper around the
/// v0.2 block cipher.
///
/// This is deliberately separate from [`RiakV2`]. It is a research
/// construction, not a standardized or externally audited AEAD. The caller
/// must never reuse a nonce with the same master key.
pub struct RiakV2Cipher {
    enc: RiakV2,
    mac: RiakV2,
}

impl RiakV2Cipher {
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
        Self::from_words(words)
    }

    /// Construct the wrapper from sixteen key words.
    pub fn from_words(key: [u32; 16]) -> Self {
        Self {
            enc: RiakV2::from_words_with_domain(key, DOMAIN_RACIK),
            mac: RiakV2::from_words_with_domain(key, DOMAIN_MAC),
        }
    }

    /// Encrypt and authenticate a message.
    ///
    /// The returned value is `ciphertext || 16-byte tag`. The caller should
    /// include its file header in `aad`.
    pub fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, V2Error> {
        let ciphertext = self.racik(nonce, plaintext, false)?;
        let tag = self.auth_tag(nonce, aad, &ciphertext)?;
        let output_capacity = ciphertext
            .len()
            .checked_add(AUTH_TAG_LEN)
            .ok_or(V2Error::LengthOverflow)?;
        let mut output = Vec::with_capacity(output_capacity);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&tag);
        Ok(output)
    }

    /// Verify and decrypt a message. No plaintext is returned before the tag
    /// verifies.
    pub fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, V2Error> {
        if sealed.len() < AUTH_TAG_LEN {
            return Err(V2Error::AuthenticationFailed);
        }
        let ciphertext_len = sealed.len() - AUTH_TAG_LEN;
        let (ciphertext, tag_bytes) = sealed.split_at(ciphertext_len);
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(tag_bytes);
        let expected = self.auth_tag(nonce, aad, ciphertext)?;
        if !constant_time_equal(&tag, &expected) {
            return Err(V2Error::AuthenticationFailed);
        }
        self.racik(nonce, ciphertext, true)
    }

    fn racik(
        &self,
        nonce: &[u8; 12],
        data: &[u8],
        decrypt: bool,
    ) -> Result<Vec<u8>, V2Error> {
        let block_count = data.len() / 16 + usize::from(data.len() % 16 != 0);
        if block_count > u32::MAX as usize {
            return Err(V2Error::CounterOverflow);
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

            // Unlike v0.1, the next state is not Z XOR C (= P). A fixed
            // mask and the block permutation make ciphertext absorption
            // explicit while remaining deterministic and invertible.
            let mut absorbed = [0u32; 4];
            let absorb_source = if decrypt { input } else { output_block };
            for (j, &byte) in absorb_source.iter().enumerate() {
                absorbed[j / 4] |= (u32::from(byte)) << (24 - 8 * (j % 4));
            }
            for word in &mut absorbed {
                *word ^= MODE_ABSORB_MASK;
            }
            state = absorbed;
            self.enc.encrypt_block(&mut state);
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
    ) -> Result<[u8; AUTH_TAG_LEN], V2Error> {
        let aad_len = u64::try_from(aad.len()).map_err(|_| V2Error::LengthOverflow)?;
        let ciphertext_len =
            u64::try_from(ciphertext.len()).map_err(|_| V2Error::LengthOverflow)?;

        let mut input = Vec::new();
        input.extend_from_slice(&MAC_CONTEXT);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&aad_len.to_le_bytes());
        input.extend_from_slice(&ciphertext_len.to_le_bytes());
        input.extend_from_slice(aad);
        input.extend_from_slice(ciphertext);

        let total_len = u64::try_from(input.len()).map_err(|_| V2Error::LengthOverflow)?;
        let mut chain = [0u32; 4];
        chain[2] = (total_len >> 32) as u32;
        chain[3] = total_len as u32;
        self.mac.encrypt_block(&mut chain);

        for chunk in input.chunks(16) {
            let mut block = [0u32; 4];
            for (j, &byte) in chunk.iter().enumerate() {
                block[j / 4] |= (u32::from(byte)) << (24 - 8 * (j % 4));
            }
            for word in 0..4 {
                chain[word] ^= block[word];
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
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn gf2_rank(images: &[u32]) -> usize {
        let mut basis = [0u32; 32];
        let mut rank = 0;
        for &image in images {
            let mut value = image;
            while value != 0 {
                let bit = 31 - value.leading_zeros() as usize;
                if basis[bit] == 0 {
                    basis[bit] = value;
                    rank += 1;
                    break;
                }
                value ^= basis[bit];
            }
        }
        rank
    }

    fn mix_images<F>(f: F) -> Vec<u32>
    where
        F: Fn(u32) -> u32,
    {
        (0..32).map(|bit| f(1u32 << bit)).collect()
    }

    #[test]
    fn all_linear_mixers_have_full_rank() {
        assert_eq!(gf2_rank(&mix_images(mix_a)), 32);
        assert_eq!(gf2_rank(&mix_images(mix_b)), 32);
        assert_eq!(gf2_rank(&mix_images(mix_c)), 32);
        assert_eq!(MUL_A & 1, 1);
        assert_eq!(MUL_B & 1, 1);
        assert_eq!(MUL_C & 1, 1);
    }

    #[test]
    fn round_function_has_no_sampled_collisions() {
        let mut state = 0x6a09_e667u32;
        let mut seen = HashSet::new();
        for _ in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let output = round_function(state, 0x1234_5678, 17);
            assert!(seen.insert(output), "unexpected F collision");
        }
    }

    #[test]
    fn block_roundtrip() {
        let cipher = RiakV2::from_words([0x1020_3040; 16]);
        let original = [0x0123_4567, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210];
        let mut block = original;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, original);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    #[test]
    fn representative_keys_have_distinct_round_keys() {
        for key in [[0u32; 16], [0xffff_ffff; 16], [0xa5a5_a5a5; 16]] {
            let cipher = RiakV2::from_words(key);
            let mut unique = HashSet::new();
            for &round_key in &cipher.round_keys {
                assert!(unique.insert(round_key), "duplicate v0.2 round key");
            }
        }
    }

    #[test]
    fn old_kernel_masks_are_not_deterministic_on_sample() {
        let cipher = RiakV2::from_words([0x3141_5926; 16]);
        for mask in [0x3333_3333u32, 0x5555_5555, 0x9999_9999] {
            let mut violations = 0usize;
            for index in 0..2_000u32 {
                let mut block = [index, index.wrapping_mul(3), 7, 11];
                let before = (block[1] & mask).count_ones() & 1;
                cipher.encrypt_block(&mut block);
                let after = (block[1] & mask).count_ones() & 1;
                violations += (before != after) as usize;
            }
            assert!(violations > 0, "old deterministic mask unexpectedly remains");
        }
    }

    #[test]
    fn reduced_round_roundtrip() {
        let cipher = RiakV2::from_words([7; 16]);
        let original = [1, 2, 3, 4];
        let mut block = original;
        cipher.encrypt_block_rounds(&mut block, 4);
        assert_ne!(block, original);
        cipher.decrypt_block_rounds(&mut block, 4);
        assert_eq!(block, original);
    }

    #[test]
    fn key_schedule_domains_are_separated() {
        let key = [0x1234_5678; 16];
        let mut first = [1, 2, 3, 4];
        let mut second = first;
        RiakV2::from_words_with_domain(key, DOMAIN_DEFAULT).encrypt_block(&mut first);
        RiakV2::from_words_with_domain(key, DOMAIN_RACIK).encrypt_block(&mut second);
        assert_ne!(first, second);
    }

    #[test]
    fn custom_seal_open_roundtrip() {
        let cipher = RiakV2Cipher::from_words([0x1357_9bdf; 16]);
        let nonce = [0x42u8; 12];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 257] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let sealed = cipher.seal(&nonce, b"RIAK2C", &plaintext).unwrap();
            assert_eq!(sealed.len(), plaintext.len() + AUTH_TAG_LEN);
            assert_eq!(cipher.open(&nonce, b"RIAK2C", &sealed).unwrap(), plaintext);
        }
    }

    #[test]
    fn custom_seal_open_many_cases() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for case in 0..128u32 {
            state ^= state << 7;
            state ^= state >> 9;
            let key: [u32; 16] = std::array::from_fn(|_| state as u32);
            let mut nonce = [0u8; 12];
            for (i, byte) in nonce.iter_mut().enumerate() {
                *byte = (state >> ((i % 8) * 8)) as u8;
            }
            let length = (state as usize) % 300;
            let plaintext: Vec<u8> = (0..length)
                .map(|i| (i as u8).wrapping_add(case as u8))
                .collect();
            let aad = [case as u8, 0xa5, 0x5a];
            let cipher = RiakV2Cipher::from_words(key);
            let sealed = cipher.seal(&nonce, &aad, &plaintext).unwrap();
            assert_eq!(cipher.open(&nonce, &aad, &sealed).unwrap(), plaintext);
        }
    }

    #[test]
    fn custom_tag_length_binding_avoids_concatenation_aliases() {
        let cipher = RiakV2Cipher::from_words([0x7777_7777; 16]);
        let first = cipher.auth_tag(&[1u8; 12], b"ab", b"c").unwrap();
        let second = cipher.auth_tag(&[1u8; 12], b"a", b"bc").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn custom_open_rejects_tampering_and_wrong_context() {
        let cipher = RiakV2Cipher::from_words([0x2468_ace0; 16]);
        let nonce = [0x24u8; 12];
        let sealed = cipher.seal(&nonce, b"header-a", b"secret").unwrap();

        let mut changed = sealed.clone();
        changed[0] ^= 1;
        assert_eq!(
            cipher.open(&nonce, b"header-a", &changed),
            Err(V2Error::AuthenticationFailed)
        );
        assert_eq!(
            cipher.open(&nonce, b"header-b", &sealed),
            Err(V2Error::AuthenticationFailed)
        );
        let mut changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        assert_eq!(
            cipher.open(&changed_nonce, b"header-a", &sealed),
            Err(V2Error::AuthenticationFailed)
        );
        let wrong_key = RiakV2Cipher::from_words([0x1111_1111; 16]);
        assert_eq!(
            wrong_key.open(&nonce, b"header-a", &sealed),
            Err(V2Error::AuthenticationFailed)
        );
    }
}
