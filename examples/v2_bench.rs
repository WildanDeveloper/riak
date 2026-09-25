//! Throughput smoke benchmark for the experimental v0.2 implementation.
//! This is not a security test and is intentionally smaller than the legacy
//! benchmark.

use riak::v2::{RiakV2, RiakV2Cipher};
use std::time::Instant;

const BYTES: usize = 16 * 1024 * 1024;

fn main() {
    let key = [0x1234_5678u32; 16];
    let cipher = RiakV2::from_words(key);
    let data = vec![0x5au8; BYTES];
    let nonce = [0x24u8; 12];
    let aad = b"RIAK2C-benchmark";

    let start = Instant::now();
    for index in 0..(BYTES / 16) {
        let mut block = [index as u32; 4];
        cipher.encrypt_block(&mut block);
        std::hint::black_box(block);
    }
    report("RIAK v0.2 block", start.elapsed().as_secs_f64());

    let wrapper = RiakV2Cipher::from_words(key);
    let start = Instant::now();
    let sealed = wrapper.seal(&nonce, aad, &data).unwrap();
    std::hint::black_box(&sealed);
    report("RIAK v0.2 seal", start.elapsed().as_secs_f64());

    let start = Instant::now();
    let opened = wrapper.open(&nonce, aad, &sealed).unwrap();
    std::hint::black_box(&opened);
    report("RIAK v0.2 open", start.elapsed().as_secs_f64());
}

fn report(label: &str, seconds: f64) {
    let mib = BYTES as f64 / 1024.0 / 1024.0 / seconds;
    println!("{label:<24} {mib:>8.1} MiB/s");
}
