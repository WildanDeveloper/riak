//! Benchmark: RIAK vs standard algorithms (AES-256, ChaCha20).
//!
//! Run: cargo run --release --example bench

#![allow(deprecated)]

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use riak::Riak;
use std::time::Instant;

const BYTES: usize = 64 * 1024 * 1024; // 64 MiB per measurement

fn fill(buf: &mut [u8]) {
    let mut x: u32 = 0x9E37_79B9;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
}

fn report(label: &str, secs: f64) {
    let mibs = BYTES as f64 / 1024.0 / 1024.0 / secs;
    println!("{:<24} {:>8.1} MiB/s", label, mibs);
}

fn main() {
    let mut data = vec![0u8; BYTES];
    fill(&mut data);

    // --- RIAK block cipher (raw block throughput) ---
    let key_words: [u32; 16] = std::array::from_fn(|i| (i as u32 + 1) * 0x1234_5679);
    let riak = Riak::from_words(key_words);
    let t = Instant::now();
    {
        let mut words;
        // process BYTES / 16 blocks
        for i in 0..(BYTES / 16) {
            words = [i as u32, i as u32, i as u32, i as u32];
            riak.encrypt_block(&mut words);
            std::hint::black_box(&words);
        }
    }
    report("RIAK block", t.elapsed().as_secs_f64());

    // --- RIAK block cipher, 4-way interleaved ---
    let t = Instant::now();
    {
        let mut quad: [[u32; 4]; 4] = [[0; 4]; 4];
        for i in 0..(BYTES / 64) {
            for (j, w) in quad.iter_mut().enumerate() {
                *w = [(i * 4 + j) as u32; 4];
            }
            riak.encrypt_block_x4(&mut quad);
            std::hint::black_box(&quad);
        }
    }
    report("RIAK block x4", t.elapsed().as_secs_f64());

    // --- RIAK "Racik" mode (streaming) ---
    let t = Instant::now();
    let _ = riak.encrypt(&[7u8; 12], &data);
    report("RIAK Racik mode", t.elapsed().as_secs_f64());

    // --- AES-256 ---
    let aes = Aes256::new_from_slice(&[0x42u8; 32]).unwrap();
    let mut buf = vec![0u8; BYTES];
    buf.copy_from_slice(&data);
    let t = Instant::now();
    for block in buf.chunks_mut(16) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        aes.encrypt_block(b);
    }
    report("AES-256 block", t.elapsed().as_secs_f64());

    // --- ChaCha20 ---
    let mut chacha = ChaCha20::new(
        chacha20::cipher::generic_array::GenericArray::from_slice(&[7u8; 32]),
        chacha20::cipher::generic_array::GenericArray::from_slice(&[1u8; 12]),
    );
    let mut buf2 = data.clone();
    let t = Instant::now();
    chacha.apply_keystream(&mut buf2);
    report("ChaCha20 stream", t.elapsed().as_secs_f64());
}
