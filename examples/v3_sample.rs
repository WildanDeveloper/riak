//! Ephemeral RIAK v0.3 sample with explicitly labeled fields.
//!
//! Run:
//!   cargo run --release --example v3_sample
//!   cargo run --release --example v3_sample -- wildanelis
//!   cargo run --release --example v3_sample -- wildanelis key.hex
//!
//! When no key file is supplied, the example generates an ephemeral key in
//! memory and never prints it. A supplied file may contain 64 raw bytes or
//! 128 hexadecimal characters. The nonce is always freshly generated.
//!
//! This is a research example, not a production key-management workflow. The
//! fixed keys in test-vector files are public, non-secret KAT fixtures and
//! must never be used to protect real data.

use riak::v3::{RiakV3Cipher, AUTH_TAG_LEN};
use std::fs;
use std::io::Read;

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn os_random(buf: &mut [u8]) {
    fs::File::open("/dev/urandom")
        .expect("cannot open /dev/urandom")
        .read_exact(buf)
        .expect("cannot read /dev/urandom");
}

fn parse_hex_key(text: &str) -> Result<[u8; 64], String> {
    let text = text.trim();
    if text.len() != 128 || !text.is_ascii() {
        return Err("hex key must contain exactly 128 ASCII hex characters".to_owned());
    }
    let mut key = [0u8; 64];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "key contains non-hex characters".to_owned())?;
    }
    Ok(key)
}

fn load_key(path: Option<&str>) -> Result<([u8; 64], String), String> {
    let Some(path) = path else {
        let mut key = [0u8; 64];
        os_random(&mut key);
        return Ok((key, "ephemeral random (not printed)".to_owned()));
    };
    let data = fs::read(path).map_err(|e| format!("cannot read key file {path}: {e}"))?;
    if data.len() == 64 {
        let mut key = [0u8; 64];
        key.copy_from_slice(&data);
        return Ok((key, format!("file:{path} (raw 64 bytes; not printed)")));
    }
    let text = std::str::from_utf8(&data)
        .map_err(|_| format!("key file {path} is neither raw bytes nor UTF-8 hex"))?;
    Ok((parse_hex_key(text)?, format!("file:{path} (hex; not printed)")))
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let plaintext = arguments
        .next()
        .unwrap_or_else(|| "wildanelis".to_owned())
        .into_bytes();
    let key_path = arguments.next();
    if arguments.next().is_some() {
        eprintln!("usage: v3_sample [plaintext] [key-file]");
        std::process::exit(2);
    }

    let (key, key_source) = load_key(key_path.as_deref()).unwrap_or_else(|error| {
        eprintln!("error: {error}");
        std::process::exit(2);
    });
    let mut nonce = [0u8; 12];
    os_random(&mut nonce);
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

    println!("RIAK v0.3 ephemeral sample (TEST ONLY)");
    println!("plaintext_text: {}", String::from_utf8_lossy(&plaintext));
    println!("plaintext_hex: {}", hex(&plaintext));
    println!("key_source: {key_source}");
    println!("nonce_hex: {}", hex(&nonce));
    println!("aad_hex: {}", hex(&header));
    println!("ciphertext_hex: {}", hex(ciphertext));
    println!("tag_hex: {}", hex(tag));
    println!("sealed_hex: {}", hex(&sealed));
    println!("riak3c_file_hex: {}", hex(&file));
    println!("decrypt_roundtrip: PASS");
}
