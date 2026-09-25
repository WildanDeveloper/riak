//! Basic statistical randomness tests on the RIAK "Racik" keystream.
//!
//! Tests: monobit frequency, block frequency (M=128), runs test.
//! These are the classic NIST SP 800-22 core tests — NOT a substitute
//! for a full TestU01 / Dieharder battery.
//!
//! Run: cargo run --release --example stats

#![allow(deprecated)]

use riak::Riak;

/// Generate keystream bytes by encrypting zero plaintext (the Racik
/// keystream blocks Z_i are exactly what protects real data).
fn keystream(cipher: &Riak, bytes: usize) -> Vec<u8> {
    cipher.encrypt(&[0x13u8; 12], &vec![0u8; bytes])
}

fn monobit(data: &[u8]) {
    let ones: u32 = data.iter().map(|b| b.count_ones()).sum();
    let n = (data.len() * 8) as f64;
    let s = 2.0 * ones as f64 - n;
    let p = erfc(s.abs() / (2.0 * n).sqrt());
    println!("monobit frequency   ones={ones:>10}  p={p:.4}  {}",
        if p < 0.01 { "FAIL" } else { "pass" });
}

fn block_frequency(data: &[u8], m: usize) {
    let blocks = data.len() / m;
    let mut chi2 = 0.0;
    for block in data.chunks(m).take(blocks) {
        let ones: u32 = block.iter().map(|b| b.count_ones()).sum();
        let pi = ones as f64 / (m as f64 * 8.0);
        chi2 += (pi - 0.5) * (pi - 0.5);
    }
    let chi2 = 4.0 * (m as f64 * 8.0) as f64 * chi2;
    // df = blocks - 1; use a normal approximation for large df
    let blocks = blocks as f64;
    let z = (chi2 - (blocks - 1.0)) / (2.0 * (blocks - 1.0)).sqrt();
    let p = 1.0 - norm_cdf(z);
    println!("block freq (M={m:>4})          p={p:.4}  {}",
        if p < 0.01 { "FAIL" } else { "pass" });
}

fn runs(data: &[u8]) {
    let n = (data.len() * 8) as f64;
    let bits: Vec<bool> = data
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1 == 1))
        .collect();
    let ones = bits.iter().filter(|&&b| b).count() as f64;
    let pi = ones / n;
    let mut runs = 1u64;
    for w in bits.windows(2) {
        if w[0] != w[1] {
            runs += 1;
        }
    }
    // NIST runs test
    let num = (runs as f64 - 2.0 * n * pi * (1.0 - pi)).abs();
    let den = 2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi);
    let p = erfc(num / den);
    println!("runs test           runs={runs:>10}  p={p:.4}  {}",
        if p < 0.01 { "FAIL" } else { "pass" });
}

fn erfc(x: f64) -> f64 {
    // Abramowitz & Stegun 7.1.26 approximation (|eps| < 1.5e-7)
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let poly = t
        * (-z * z
            - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587
                                        + t * (-0.82215223
                                            + t * 0.17087277)))))))));
    let tau = poly.exp();
    if x >= 0.0 { tau } else { 2.0 - tau }
}

fn norm_cdf(x: f64) -> f64 {
    0.5 * erfc(-x / (2.0_f64).sqrt())
}

fn main() {
    let cipher = Riak::from_words(std::array::from_fn(|i| (i as u32 + 3) * 0x9E37_79B9));
    const MB: usize = 8 * 1024 * 1024;
    let ks = keystream(&cipher, MB);
    println!("keystream: {} bytes\n", MB);
    monobit(&ks);
    block_frequency(&ks, 128);
    block_frequency(&ks, 4096);
    runs(&ks);
    println!("\nNote: p >= 0.01 passes these classic tests. Passing here is");
    println!("necessary, not sufficient — a full TestU01/Dieharder battery");
    println!("is still on the roadmap.");
}
