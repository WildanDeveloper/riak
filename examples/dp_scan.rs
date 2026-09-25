//! DP of the round function F for structured (low-weight) input
//! differences — the kind an attacker would use to start a trail.
//!
//! Random input differences were probed in ddt.rs (max DP ≈ 2^-11).
//! This scan covers ALL 1-bit and 2-bit input differences, which the
//! minimal trails from trail_search favor (their early active rounds
//! have attacker-chosen differences).
//!
//! Run: cargo run --release --example dp_scan

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

fn f(x: u32, k: u32, c: u32) -> u32 {
    const MUL: u32 = 0x9E37_79B9;
    let mut t = x ^ k;
    t = t.wrapping_add(c);
    t = t.wrapping_mul(MUL);
    t ^= t.rotate_left(9);
    t ^= t.rotate_left(17);
    t ^= t.rotate_left(23);
    t
}

fn main() {
    let mut rng = Rng(0xB105_F00D_C0FF_EE00);
    const KEY: u32 = 0xA5A5_5A5A;
    const C: u32 = 17;
    const SAMPLES: u32 = 1 << 24;

    // All 1-bit differences (32) + all 2-bit differences (496).
    let mut diffs: Vec<u32> = Vec::new();
    for i in 0..32u32 {
        diffs.push(1 << i);
    }
    for i in 0..32u32 {
        for j in (i + 1)..32u32 {
            diffs.push((1 << i) | (1 << j));
        }
    }

    println!("scanning {} low-weight input differences, {SAMPLES} samples each\n", diffs.len());

    let mut results: Vec<(f64, u32, u32)> = Vec::new(); // (dp, dx, dy)
    for &dx in &diffs {
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for _ in 0..SAMPLES {
            let x = rng.word();
            let dy = f(x, KEY, C) ^ f(x ^ dx, KEY, C);
            *counts.entry(dy).or_insert(0) += 1;
        }
        let (dy, &hits) = counts.iter().max_by_key(|(_, c)| **c).unwrap();
        results.push((hits as f64 / SAMPLES as f64, dx, *dy));
    }

    results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    println!("top 10 low-weight differences by max DP:");
    println!("{:>4} {:>12} {:>12} {:>10}", "rank", "dx", "dy", "DP");
    for (i, (dp, dx, dy)) in results.iter().take(10).enumerate() {
        println!(
            "{:>4} {:>12} {:>12} {:>10} (2^{:.1})",
            i + 1,
            format!("{dx:08x}"),
            format!("{dy:08x}"),
            dp,
            dp.log2()
        );
    }

    let top = results[0].0;
    println!("\nmax DP over all low-weight differences: {top:.3e} (2^{:.1})", top.log2());
    println!("random-difference max DP (ddt.rs):      5.0e-4 (2^-11.0)");
    if top > 1.0e-3 {
        println!("NOTE: low-weight differences are BETTER for the attacker —");
        println!("use this value in the trail bound instead of 2^-11.");
    } else {
        println!("low-weight differences are no better than random ones.");
    }
}
