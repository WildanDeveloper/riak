//! Focused verification of the highest-DP input differences found by
//! the DDT probe (`ddt.rs`). Re-estimates their differential
//! probability with a much larger sample and checks reproducibility.
//!
//! Run: cargo run --release --example ddt_focus

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
    let mut rng = Rng(0xF00D_5EED_1111_2222);
    const SAMPLES: u32 = 1 << 24; // 256x the probe sample
    const KEY: u32 = 0xA5A5_5A5A;
    const C: u32 = 17;

    // Top differences from the DDT probe.
    let candidates: [u32; 5] = [
        0xE5D5_FFDE,
        0x4636_2400,
        0x54B6_0410,
        0x02AA_4080,
        0x3FF6_FFA1,
    ];

    println!("Re-estimate DP with {SAMPLES} samples per difference:\n");
    for &dx in &candidates {
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for _ in 0..SAMPLES {
            let x = rng.word();
            let dy = f(x, KEY, C) ^ f(x ^ dx, KEY, C);
            *counts.entry(dy).or_insert(0) += 1;
        }
        let (dy, &hits) = counts.iter().max_by_key(|(_, c)| **c).unwrap();
        let dp = hits as f64 / SAMPLES as f64;
        println!(
            "dx={dx:08x}  top dy={dy:08x}  hits={hits:>9}  DP={dp:.3e} (2^{:.1})",
            dp.log2()
        );
    }

    println!("\nReference points:");
    println!("  AES S-box max DP:        2^-6  (= 1.5e-2)");
    println!("  good 32-bit ARX max DP:  ~2^-13..2^-17");
    println!("  chance level here:       {:.1e}", 1.0 / SAMPLES as f64);
}
