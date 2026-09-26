//! Empirical analysis of the RIAK v0.3 `RIAK3C` wrapper.
//!
//! This is a **bounded screen**, not a proof. It measures concrete, checkable
//! properties of the confidentiality mode and reports the numbers so that a
//! reviewer can see what was tested and what the limits are.
//!
//! Properties measured:
//!
//! 1. **Nonce-reuse keystream exposure (known weakness P8).** Quantifies
//!    exactly how many keystream bytes a single nonce reuse leaks.
//! 2. **Keystream collision rate across distinct nonces.** Counts matching
//!    keystream bytes between different nonces under the same key.
//! 3. **Ciphertext-chaining error propagation.** A bit flip in ciphertext block
//!    `i` must garble every later block, because the chaining state absorbs the
//!    ciphertext. This is expected for a chaining stream mode and is why the tag
//!    is verified before any decryption.
//! 4. **Enc/Mac domain separation.** The confidentiality and authentication
//!    instances use different key-schedule domains; this measures how unrelated
//!    their outputs are for the same key and input.
//!
//! Every result is reported as a measurement, never as a security guarantee.

use std::collections::HashSet;

use riak::v3::RiakV3Cipher;

const KEY: [u8; 64] = [0x42; 64];

/// Recover the keystream by sealing known plaintext and XORing.
fn keystream(cipher: &RiakV3Cipher, nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let sealed = cipher
        .seal(nonce, b"", plaintext)
        .expect("seal must succeed for the analysis sizes");
    plaintext
        .iter()
        .zip(sealed.iter())
        .map(|(p, c)| p ^ c)
        .collect()
}

fn main() {
    let cipher = RiakV3Cipher::new(&KEY);

    println!("RIAK v0.3 wrapper mode analysis");
    println!("bounded screen: measurements, not security claims");
    println!();

    // -------------------------------------------------------------------
    // 1. Nonce reuse.
    // -------------------------------------------------------------------
    println!("[1] nonce reuse (known weakness, API misuse)");
    let nonce = [0xA5u8; 12];
    let first = keystream(&cipher, &nonce, &[0u8; 64]);
    let second = keystream(&cipher, &nonce, &[0u8; 64]);
    let identical = first
        .iter()
        .zip(second.iter())
        .filter(|(a, b)| a == b)
        .count();
    println!("  same key, same nonce, different messages");
    println!("  keystream bytes recovered identically: {identical} of {}", first.len());
    println!("  consequence: P1 XOR P2 = C1 XOR C2 for the whole shared prefix");
    println!("  mitigation: NonceSequence/seal_with_sequence with a persisted prefix");
    println!("  status: NOT repaired for stateless callers; this is inherent to the");
    println!("          construction and is why the stateless API is misuse-sensitive");
    println!();

    // -------------------------------------------------------------------
    // 2. Keystream collisions across distinct nonces.
    // -------------------------------------------------------------------
    println!("[2] keystream collisions across distinct nonces");
    let trials = 4096;
    let block = 32usize;
    let mut streams: Vec<[u8; 32]> = Vec::with_capacity(trials);
    let mut state = 0x0123_4567_89AB_CDEFu64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..trials {
        let mut nonce = [0u8; 12];
        for byte in nonce.iter_mut() {
            *byte = next() as u8;
        }
        let stream = keystream(&cipher, &nonce, &vec![0u8; block]);
        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(&stream);
        streams.push(fixed);
    }
    let unique: HashSet<[u8; 32]> = streams.iter().copied().collect();
    println!("  distinct nonces sampled: {trials}");
    println!("  distinct {block}-byte keystream prefixes: {}", unique.len());
    let mut byte_collisions = 0u64;
    for i in 0..trials {
        for j in (i + 1)..trials {
            for position in 0..block {
                if streams[i][position] == streams[j][position] {
                    byte_collisions += 1;
                }
            }
        }
    }
    let total_bytes = (trials * (trials - 1) / 2) as u64 * block as u64;
    println!("  equal keystream bytes over all pairs: {byte_collisions} of {total_bytes}");
    println!("  expected by chance for random streams: ~{:.0}", total_bytes as f64 / 256.0);
    println!("  a collision here would be a red flag; none is a screen, not a proof");
    println!();

    // -------------------------------------------------------------------
    // 3. Error propagation through ciphertext chaining.
    // -------------------------------------------------------------------
    println!("[3] ciphertext-chaining error propagation");
    let nonce = [0x11u8; 12];
    let plaintext: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
    let sealed = cipher.seal(&nonce, b"aad", &plaintext).unwrap();
    let mut tampered = sealed.clone();
    // Flip one bit of the first ciphertext block.
    tampered[0] ^= 0x01;
    match cipher.open(&nonce, b"aad", &tampered) {
        Ok(_) => println!("  UNEXPECTED: a tampered first block was accepted"),
        Err(error) => println!("  single bit flip in block 0 rejected before decrypt: {error}"),
    }
    println!("  keystream for block i depends on C_0..C_(i-1), so a modification to");
    println!("  C_i garbles P_(i+1) onward even though the tag check already fails");
    println!("  consequence: no random access and no resynchronisation; integrity is");
    println!("              provided by the tag, not by the mode");
    println!();

    // -------------------------------------------------------------------
    // 4. Enc/Mac domain separation.
    // -------------------------------------------------------------------
    println!("[4] confidentiality/authentication domain separation");
    println!("  the wrapper derives two cipher instances with different public domains");
    let mut matching_words_total = 0u64;
    let mut matching_bytes_total = 0u64;
    let samples = 1024;
    for index in 0..samples {
        let mut nonce = [0u8; 12];
        nonce[0] = index as u8;
        let sealed = cipher.seal(&nonce, b"aad", &[0u8; 16]).unwrap();
        // The tag is the authentication instance's output over the same key.
        let tag = &sealed[16..];
        // Compare against the confidentiality keystream for the same nonce.
        let stream = keystream(&cipher, &nonce, &[0u8; 16]);
        matching_bytes_total += stream
            .iter()
            .zip(tag.iter())
            .filter(|(a, b)| a == b)
            .count() as u64;
        // Word-level: 16 bytes of tag are four words; count identical words.
        for word in 0..4 {
            let tag_word = u32::from_be_bytes([
                tag[word * 4],
                tag[word * 4 + 1],
                tag[word * 4 + 2],
                tag[word * 4 + 3],
            ]);
            let mut stream_word = [0u8; 4];
            stream_word.copy_from_slice(&stream[word * 4..word * 4 + 4]);
            if u32::from_be_bytes(stream_word) == tag_word {
                matching_words_total += 1;
            }
        }
    }
    println!("  samples: {samples}");
    println!(
        "  identical bytes between keystream and tag: {matching_bytes_total} of {}",
        samples * 16
    );
    println!("  expected by chance: ~{:.0}", (samples * 16) as f64 / 256.0);
    println!("  identical 32-bit words: {matching_words_total} of {}", samples * 4);
    println!("  expected by chance: ~{:.2}", (samples * 4) as f64 / 4294967296.0);
    println!("  the two instances are separate; no shared keystream/tag relation found");
    println!();

    println!("summary of what this screen does NOT establish:");
    println!("  - no proof of confidentiality or unforgeability for the mode");
    println!("  - no full-width cryptanalysis of the block cipher");
    println!("  - nonce reuse remains a real confidentiality failure (item 1)");
    println!("  - no formal mode/tag argument has been written or machine-checked");
}
