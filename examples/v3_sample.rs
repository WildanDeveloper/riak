//! Deterministic RIAK v0.3 sample with explicitly labeled fields.
//!
//! Run:
//!   cargo run --release --example v3_sample
//!   cargo run --release --example v3_sample -- wildan
//!
//! This uses a public test key and a fixed nonce for reproducibility. It is
//! not a production example. The CLI uses a random nonce and will not produce
//! this exact file.

use riak::v3::{RiakV3Cipher, AUTH_TAG_LEN};

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn main() {
    let plaintext = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wildan".to_owned());
    let plaintext = plaintext.into_bytes();

    let key_words: [u32; 16] = [
        0xdead_beef,
        0xcafe_babe,
        0x1234_5678,
        0x9abc_def0,
        0x0f1e_2d3c,
        0x4b5a_6978,
        0x87c6_9d5e,
        0x30a4_b7c1,
        0x55aa_55aa,
        0xff00_ff00,
        0x0123_4567,
        0x89ab_cdef,
        0xdead_beef,
        0xcafe_babe,
        0x1357_9bdf,
        0x2468_ace0,
    ];
    let mut key = [0u8; 64];
    for (i, word) in key_words.iter().enumerate() {
        key[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }

    let nonce = [
        0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let mut header = b"RIAK3C".to_vec();
    header.extend_from_slice(&nonce);

    let cipher = RiakV3Cipher::new(&key);
    let sealed = cipher.seal(&nonce, &header, &plaintext).unwrap();
    let ciphertext = &sealed[..sealed.len() - AUTH_TAG_LEN];
    let tag = &sealed[sealed.len() - AUTH_TAG_LEN..];
    let mut file = header.clone();
    file.extend_from_slice(&sealed);
    let opened = cipher.open(&nonce, &header, &sealed).unwrap();
    assert_eq!(opened, plaintext);

    println!("RIAK v0.3 deterministic sample (TEST ONLY)");
    println!("plaintext_text: {}", String::from_utf8_lossy(&plaintext));
    println!("plaintext_hex: {}", hex(&plaintext));
    println!("key_hex: {}", hex(&key));
    println!("nonce_hex: {}", hex(&nonce));
    println!("aad_hex: {}", hex(&header));
    println!("ciphertext_hex: {}", hex(ciphertext));
    println!("tag_hex: {}", hex(tag));
    println!("sealed_hex: {}", hex(&sealed));
    println!("riak3c_file_hex: {}", hex(&file));
    println!("decrypt_roundtrip: PASS");
}
