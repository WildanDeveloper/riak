//! Empirical DDT scan for the experimental v0.2 round function.
//!
//! This is a screening tool, not a proof of differential security.
//! Run: cargo run --release --example v2_ddt

use riak::v2::round_function;
use std::collections::HashMap;

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
    const RANDOM_DIFFS: usize = 512;
    const RANDOM_SAMPLES: u32 = 1 << 16;
    const LOW_WEIGHT_SAMPLES: u32 = 1 << 18;
    const KEY: u32 = 0xA5A5_5A5A;
    const CONST: u32 = 17;
    let mut rng = Rng(0xD1CE_DD00_1234_5678);

    let mut random_results = Vec::with_capacity(RANDOM_DIFFS);
    for _ in 0..RANDOM_DIFFS {
        let dx = rng.word();
        let mut counts = HashMap::new();
        for _ in 0..RANDOM_SAMPLES {
            let x = rng.word();
            let dy = round_function(x, KEY, CONST)
                ^ round_function(x ^ dx, KEY, CONST);
            *counts.entry(dy).or_insert(0u32) += 1;
        }
        let (dy, hits) = counts.iter().max_by_key(|(_, count)| **count).unwrap();
        random_results.push((*hits, dx, *dy));
    }
    random_results.sort_by(|a, b| b.0.cmp(&a.0));
    println!("random input differences ({RANDOM_DIFFS} × 2^16 samples)");
    for (hits, dx, dy) in random_results.iter().take(5) {
        println!(
            "  dx={dx:08x} dy={dy:08x} hits={hits:>6} dp={:.3e}",
            *hits as f64 / RANDOM_SAMPLES as f64
        );
    }

    let mut low_weight = Vec::new();
    for bit in 0..32u32 {
        low_weight.push(1u32 << bit);
    }
    for first in 0..32u32 {
        for second in (first + 1)..32u32 {
            low_weight.push((1u32 << first) | (1u32 << second));
        }
    }

    let mut low_results = Vec::with_capacity(low_weight.len());
    for dx in low_weight {
        let mut counts = HashMap::new();
        for _ in 0..LOW_WEIGHT_SAMPLES {
            let x = rng.word();
            let dy = round_function(x, KEY, CONST)
                ^ round_function(x ^ dx, KEY, CONST);
            *counts.entry(dy).or_insert(0u32) += 1;
        }
        let (dy, hits) = counts.iter().max_by_key(|(_, count)| **count).unwrap();
        low_results.push((*hits, dx, *dy));
    }
    low_results.sort_by(|a, b| b.0.cmp(&a.0));
    println!("\nlow-weight input differences (1/2 bit × 2^18 samples)");
    for (hits, dx, dy) in low_results.iter().take(10) {
        println!(
            "  dx={dx:08x} dy={dy:08x} hits={hits:>7} dp={:.3e}",
            *hits as f64 / LOW_WEIGHT_SAMPLES as f64
        );
    }
}
