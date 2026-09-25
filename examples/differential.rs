//! RIAK differential cryptanalysis tool.
//!
//! Measures empirical Differential Probability (DP): for a fixed input
//! difference, feed many random plaintext pairs and check how
//! concentrated the output differences are. High DP (far above 2^-128)
//! means an exploitable differential.
//!
//! Run: cargo run --release --example differential

#![allow(deprecated)]

use riak::Riak;
use std::collections::HashMap;

/// xorshift64* — PRNG good enough for experiments (NOT for security).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn word(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }
}

fn main() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    // Fixed random key for the whole experiment.
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = Riak::from_words(key);

    // Representative input differences:
    // - single bit (the classic starter attack)
    // - difference in the last word (hits round 1 immediately)
    // - full-word and full-state differences
    let diffs: [(&str, [u32; 4]); 4] = [
        ("1-bit X0", [1, 0, 0, 0]),
        ("1-bit X3", [0, 0, 0, 0x8000_0000]),
        ("full-X0", [0xFFFF_FFFF, 0, 0, 0]),
        ("full-all", [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF]),
    ];

    // Ideal DP target is ~2^-128, so expect ~0 collisions.
    // For round-reduced versions we use 2^20 pairs per cell.
    const TRIALS: u64 = 1 << 20;

    println!(
        "{:<14} {:>6} {:>34} {:>12}",
        "difference", "round", "top delta-output", "hits/2^20"
    );

    for rounds in [4usize, 6, 8, 10, 12, 16, 24] {
        for (label, dx) in &diffs {
            let mut counts: HashMap<[u32; 4], u32> = HashMap::new();
            for _ in 0..TRIALS {
                let a: [u32; 4] = std::array::from_fn(|_| rng.word());
                let mut b = [
                    a[0] ^ dx[0],
                    a[1] ^ dx[1],
                    a[2] ^ dx[2],
                    a[3] ^ dx[3],
                ];
                let mut ca = a;
                cipher.encrypt_block_rounds(&mut ca, rounds);
                cipher.encrypt_block_rounds(&mut b, rounds);
                let dy = [
                    ca[0] ^ b[0],
                    ca[1] ^ b[1],
                    ca[2] ^ b[2],
                    ca[3] ^ b[3],
                ];
                *counts.entry(dy).or_insert(0) += 1;
            }
            let (top_dy, &hits) = counts.iter().max_by_key(|(_, c)| **c).unwrap();
            println!(
                "{:<14} {:>6} {:>34} {:>12}",
                label,
                rounds,
                format!("{:08x}{:08x}{:08x}{:08x}", top_dy[0], top_dy[1], top_dy[2], top_dy[3]),
                hits
            );
        }
        println!();
    }

    println!("Note: for an ideal cipher, with 2^20 pairs the top count");
    println!("should be ~1 (pure chance collisions). A large, stable count");
    println!("means a differential characteristic — an exploitable gap.");
}
