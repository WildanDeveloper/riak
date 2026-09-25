//! Throughput smoke benchmark for the experimental v0.3 implementation.
//! This is a performance measurement, not a security test.

use riak::v3::{RiakV3, RiakV3Cipher};
use std::time::Instant;

const BYTES: usize = 8 * 1024 * 1024;

fn main() {
    let key = [0x1234_5678u32; 16];
    let cipher = RiakV3::from_words(key);
    let data = vec![0x5au8; BYTES];
    let nonce = [0x24u8; 12];
    let aad = b"RIAK3C-benchmark";

    let start = Instant::now();
    for index in 0..(BYTES / 16) {
        let mut block = [index as u32; 4];
        cipher.encrypt_block(&mut block);
        std::hint::black_box(block);
    }
    report("RIAK v0.3 block", start.elapsed().as_secs_f64());

    let start = Instant::now();
    for _ in 0..1_000 {
        let cipher = RiakV3::from_words(key);
        std::hint::black_box(&cipher);
    }
    let setup_ns = start.elapsed().as_secs_f64() * 1e9 / 1_000.0;
    println!("RIAK v0.3 key setup          {setup_ns:>8.1} ns");

    let start = Instant::now();
    let mut blocks = [[0u32; 4]; 4];
    for index in 0..(BYTES / 16 / 4) {
        for lane in 0..4 {
            blocks[lane] = [index as u32 + lane as u32; 4];
        }
        cipher.encrypt_block_x4(&mut blocks);
        std::hint::black_box(blocks);
    }
    report("RIAK v0.3 block x4", start.elapsed().as_secs_f64());

    let wrapper = RiakV3Cipher::from_words(key);
    let start = Instant::now();
    let sealed = wrapper.seal(&nonce, aad, &data).unwrap();
    std::hint::black_box(&sealed);
    report("RIAK v0.3 seal", start.elapsed().as_secs_f64());

    let start = Instant::now();
    let opened = wrapper.open(&nonce, aad, &sealed).unwrap();
    std::hint::black_box(&opened);
    report("RIAK v0.3 open", start.elapsed().as_secs_f64());
}

fn report(label: &str, seconds: f64) {
    let mib = BYTES as f64 / 1024.0 / 1024.0 / seconds;
    println!("{label:<24} {mib:>8.1} MiB/s");
}
