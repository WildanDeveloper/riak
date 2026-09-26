use riak::v3::{RiakV3Cipher, V3Error, AUTH_TAG_LEN};

fn cipher() -> RiakV3Cipher {
    RiakV3Cipher::from_words([
        0x1020_3040, 0x5060_7080, 0x90a0_b0c0, 0xd0e0_f001,
        0x1234_5678, 0x9abc_def0, 0x0f1e_2d3c, 0x4b5a_6978,
        0x87c6_9d5e, 0x30a4_b7c1, 0x55aa_55aa, 0xff00_ff00,
        0x0123_4567, 0x89ab_cdef, 0xdead_beef, 0xcafe_babe,
    ])
}

#[test]
fn lengths_and_empty_partial_blocks_roundtrip() {
    let cipher = cipher();
    let nonce = [0x11u8; 12];
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 255, 4096] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 13 + 7) as u8).collect();
        let sealed = cipher.seal(&nonce, b"length-aad", &plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + AUTH_TAG_LEN);
        assert_eq!(
            cipher.open(&nonce, b"length-aad", &sealed).unwrap(),
            plaintext
        );
    }
}

#[test]
fn every_tag_byte_and_ciphertext_byte_is_authenticated() {
    let cipher = cipher();
    let nonce = [0x22u8; 12];
    let plaintext = b"a message long enough for mutations";
    let sealed = cipher.seal(&nonce, b"aad", plaintext).unwrap();

    for index in 0..AUTH_TAG_LEN {
        let mut changed = sealed.clone();
        changed[plaintext.len() + index] ^= 0x80;
        assert_eq!(
            cipher.open(&nonce, b"aad", &changed),
            Err(V3Error::AuthenticationFailed),
            "tag byte {index} was not checked"
        );
    }
    for index in 0..plaintext.len() {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        assert_eq!(
            cipher.open(&nonce, b"aad", &changed),
            Err(V3Error::AuthenticationFailed),
            "ciphertext byte {index} was not checked"
        );
    }
}

#[test]
fn aad_nonce_key_and_length_are_bound() {
    let cipher = cipher();
    let other = RiakV3Cipher::from_words([0x1111_1111; 16]);
    let nonce = [0x33u8; 12];
    let sealed = cipher.seal(&nonce, b"left", b"same ciphertext").unwrap();
    assert!(cipher.open(&nonce, b"right", &sealed).is_err());
    assert!(cipher.open(&[0x34u8; 12], b"left", &sealed).is_err());
    assert!(other.open(&nonce, b"left", &sealed).is_err());

    let a = cipher.seal(&nonce, b"ab", b"c").unwrap();
    let b = cipher.seal(&nonce, b"a", b"c").unwrap();
    assert_eq!(a[..a.len() - AUTH_TAG_LEN], b[..b.len() - AUTH_TAG_LEN]);
    assert_ne!(
        a[a.len() - AUTH_TAG_LEN..],
        b[b.len() - AUTH_TAG_LEN..],
        "AAD boundary was not authenticated"
    );

    let c = cipher.seal(&nonce, b"a", b"bc").unwrap();
    assert_ne!(a, c, "ciphertext length boundary was not authenticated");
}

#[test]
fn chaining_uses_absorbed_ciphertext_and_nonce_reuse_is_visible() {
    let cipher = cipher();
    let nonce = [0x44u8; 12];
    let prefix = [0x55u8; 16];
    let mut plaintext_a = prefix.to_vec();
    plaintext_a.extend_from_slice(b"A");
    let mut plaintext_b = prefix.to_vec();
    plaintext_b.extend_from_slice(b"B");
    let sealed_a = cipher.seal(&nonce, b"aad", &plaintext_a).unwrap();
    let sealed_b = cipher.seal(&nonce, b"aad", &plaintext_b).unwrap();

    assert_eq!(&sealed_a[..16], &sealed_b[..16]);
    assert_ne!(&sealed_a[16..32], &sealed_b[16..32]);

    // Reusing a nonce has the expected CTR first-block XOR leakage. This is a
    // documented prohibition, not a claim that the mode repairs nonce reuse.
    let xor_first: Vec<u8> = plaintext_a
        .iter()
        .zip(plaintext_b.iter())
        .take(16)
        .map(|(a, b)| a ^ b)
        .collect();
    let ciphertext_xor: Vec<u8> = sealed_a
        .iter()
        .zip(sealed_b.iter())
        .take(16)
        .map(|(a, b)| a ^ b)
        .collect();
    assert_eq!(xor_first, ciphertext_xor);
}

#[test]
fn truncation_and_extension_are_rejected() {
    let cipher = cipher();
    let nonce = [0x77u8; 12];
    let plaintext: Vec<u8> = (0..80u32).map(|i| (i * 7) as u8).collect();
    let sealed = cipher.seal(&nonce, b"aad", &plaintext).unwrap();

    // Every truncation must fail: the tag binds the ciphertext length, so a
    // short sealed value cannot be reinterpreted as a shorter message.
    for cut in 1..sealed.len() {
        let truncated = &sealed[..cut];
        let result = cipher.open(&nonce, b"aad", truncated);
        assert!(
            result.is_err(),
            "truncating to {cut} bytes was accepted; length binding is broken"
        );
    }

    // Extending the ciphertext must fail as well.
    let mut extended = sealed.clone();
    extended[0] ^= 0x00; // no-op byte write, then append
    extended.push(0x00);
    assert!(cipher.open(&nonce, b"aad", &extended).is_err());
    let mut extended_block = sealed.clone();
    extended_block.extend_from_slice(&[0u8; 16]);
    assert!(cipher.open(&nonce, b"aad", &extended_block).is_err());
}

#[test]
fn empty_ciphertext_is_distinct_from_absent_ciphertext() {
    let cipher = cipher();
    let nonce = [0x99u8; 12];
    // Sealing an empty message still produces a tag, and it must not equal the
    // tag of a non-empty message under the same nonce and aad.
    let empty = cipher.seal(&nonce, b"aad", b"").unwrap();
    assert_eq!(empty.len(), AUTH_TAG_LEN);
    let nonempty = cipher.seal(&nonce, b"aad", b"\x00").unwrap();
    assert_ne!(empty, nonempty[..AUTH_TAG_LEN]);
    assert_eq!(cipher.open(&nonce, b"aad", &empty).unwrap(), Vec::<u8>::new());
}

#[test]
fn chaining_state_follows_absorbed_ciphertext_exactly() {
    // The chaining state absorbs the ciphertext, so the keystream for block i is
    // determined by the prefix C_0..C_(i-1) and nothing else.
    //
    // The two messages below deliberately share a nonce so that the first
    // ciphertext block, and therefore the state entering block 1, are identical.
    // Reusing a nonce is a prohibited misuse (see the dedicated test and P8), but
    // it is the only way to isolate the chaining dependency from nonce binding.
    let cipher = cipher();
    let nonce = [0x5Au8; 12];

    let a = vec![0x10u8; 48];
    let mut b = a.clone();
    // Block 0 identical, block 1 differs, block 2 identical again.
    b[16] ^= 0x01;

    let sealed_a = cipher.seal(&nonce, b"aad", &a).unwrap();
    let sealed_b = cipher.seal(&nonce, b"aad", &b).unwrap();

    // Identical plaintext block 0 under the same nonce gives identical C_0.
    assert_eq!(&sealed_a[..16], &sealed_b[..16]);

    // The keystream for block 1 is a function of the state after block 0 only.
    // Since that state is identical, the keystream must be identical, and the
    // ciphertext difference must equal the plaintext difference exactly.
    let ks_a1: Vec<u8> = a[16..32].iter().zip(&sealed_a[16..32]).map(|(p, c)| p ^ c).collect();
    let ks_b1: Vec<u8> = b[16..32].iter().zip(&sealed_b[16..32]).map(|(p, c)| p ^ c).collect();
    assert_eq!(ks_a1, ks_b1, "block 1 keystream must depend only on the block 0 prefix");

    // Block 1 ciphertext now differs, so the state entering block 2 differs and
    // the block 2 keystream must diverge even though the block 2 plaintext is
    // byte-for-byte identical in both messages. That makes the divergence
    // attributable to the chaining state alone.
    assert_ne!(&sealed_a[16..32], &sealed_b[16..32]);
    assert_eq!(a[32..48], b[32..48], "block 2 plaintext must stay identical");
    let ks_a2: Vec<u8> = a[32..48].iter().zip(&sealed_a[32..48]).map(|(p, c)| p ^ c).collect();
    let ks_b2: Vec<u8> = b[32..48].iter().zip(&sealed_b[32..48]).map(|(p, c)| p ^ c).collect();
    assert_ne!(ks_a2, ks_b2, "block 2 keystream must follow the changed chaining state");
    assert_ne!(&sealed_a[32..48], &sealed_b[32..48]);

    // Both messages are still correctly recoverable.
    assert_eq!(cipher.open(&nonce, b"aad", &sealed_a).unwrap(), a);
    assert_eq!(cipher.open(&nonce, b"aad", &sealed_b).unwrap(), b);
}

#[test]
fn nonce_sequence_survives_resume_and_refuses_exhaustion() {
    use riak::nonce::{NonceError, NonceSequence};

    let cipher = cipher();
    let prefix = [0x7Eu8; 8];

    // Two separate processes resuming from a persisted counter must not collide.
    let mut first = NonceSequence::new(prefix);
    let (nonce_a, sealed_a) = cipher
        .seal_with_sequence(&mut first, b"aad", b"first")
        .unwrap();
    let issued = first.issued();

    let mut resumed = NonceSequence::resume(prefix, issued);
    let (nonce_b, sealed_b) = cipher
        .seal_with_sequence(&mut resumed, b"aad", b"second")
        .unwrap();
    assert_ne!(nonce_a, nonce_b);
    assert_eq!(cipher.open(&nonce_a, b"aad", &sealed_a).unwrap(), b"first");
    assert_eq!(cipher.open(&nonce_b, b"aad", &sealed_b).unwrap(), b"second");

    // Resuming from zero with the same prefix would repeat a nonce, which is the
    // misuse the API exists to make visible.
    let mut restarted = NonceSequence::resume(prefix, 0);
    let (nonce_c, _) = cipher
        .seal_with_sequence(&mut restarted, b"aad", b"third")
        .unwrap();
    assert_eq!(nonce_c, nonce_a, "resume(0) repeated a nonce, as expected");

    // Exhaustion must be an explicit error, never a wrap-around.
    let mut almost_done = NonceSequence::resume(prefix, u32::MAX);
    let (last, _) = cipher
        .seal_with_sequence(&mut almost_done, b"aad", b"last")
        .unwrap();
    assert_eq!(last[8..], u32::MAX.to_be_bytes());
    assert_eq!(almost_done.next(), Err(NonceError::CounterExhausted));
    assert_eq!(
        cipher
            .seal_with_sequence(&mut almost_done, b"aad", b"overflow")
            .unwrap_err(),
        V3Error::NonceExhausted
    );
}

#[test]
fn deterministic_randomized_seal_open_cases() {
    let mut state = 0x0123_4567_89ab_cdefu64;
    let mut next = || {
        state ^= state << 7;
        state ^= state >> 9;
        state
    };
    for case in 0..128usize {
        let key: [u32; 16] = std::array::from_fn(|_| next() as u32);
        let cipher = RiakV3Cipher::from_words(key);
        let mut nonce = [0u8; 12];
        for byte in &mut nonce {
            *byte = next() as u8;
        }
        let aad_len = (next() as usize) % 41;
        let plaintext_len = (next() as usize) % 513;
        let aad: Vec<u8> = (0..aad_len).map(|i| (i as u8) ^ next() as u8).collect();
        let plaintext: Vec<u8> = (0..plaintext_len)
            .map(|i| (i as u8).wrapping_add(next() as u8))
            .collect();
        let sealed = cipher.seal(&nonce, &aad, &plaintext).unwrap();
        assert_eq!(cipher.open(&nonce, &aad, &sealed).unwrap(), plaintext);
        if !sealed.is_empty() {
            let mut changed = sealed.clone();
            let index = (next() as usize) % sealed.len();
            changed[index] ^= 1;
            assert!(cipher.open(&nonce, &aad, &changed).is_err(), "case={case}");
        }
    }
}

#[test]
fn short_input_and_wrong_context_are_rejected_before_plaintext() {
    let cipher = cipher();
    let nonce = [0x66u8; 12];
    assert_eq!(
        cipher.open(&nonce, b"aad", &[0u8; AUTH_TAG_LEN - 1]),
        Err(V3Error::AuthenticationFailed)
    );
    let sealed = cipher.seal(&nonce, b"aad", b"data").unwrap();
    assert!(cipher.open(&nonce, b"different", &sealed).is_err());
    assert_eq!(cipher.open(&nonce, b"aad", &sealed).unwrap(), b"data");
}
