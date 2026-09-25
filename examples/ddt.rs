//! Empirical DDT (Differential Distribution Table) probe of the round
//! function F.
//!
//! For each sampled input difference dx, estimate the differential
//! probability of every output difference by sampling. F has no
//! exploitable weak spot if the maximum DP stays near the ideal
//! level for a random 32-bit permutation (~2^-32 per specific pair,
//! i.e. collisions only at chance level in the sample).
//!
//! Run: cargo run --release --example ddt

use std::collections::HashMap;

/// xorshift64* — experiment PRNG (NOT for security).
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

/// Mirror of the private round function F (kept in sync with lib.rs
/// via the cross-validated test vectors — if they diverge, the
/// `match_python_vectors` test breaks first).
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
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    const DIFFS: usize = 2000; // random input differences to probe
    const SAMPLES: u32 = 1 << 16; // x values per difference
    const KEY: u32 = 0xA5A5_5A5A;
    const C: u32 = 17; // a prime round constant

    let mut results: Vec<(f64, u32, u32, u32)> = Vec::new(); // (dp, dx, dy, hits)

    for _ in 0..DIFFS {
        let dx = rng.word();
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for _ in 0..SAMPLES {
            let x = rng.word();
            let dy = f(x, KEY, C) ^ f(x ^ dx, KEY, C);
            *counts.entry(dy).or_insert(0) += 1;
        }
        let (dy, &hits) = counts.iter().max_by_key(|(_, c)| **c).unwrap();
        results.push((hits as f64 / SAMPLES as f64, dx, *dy, hits));    }

    results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    println!("Top 10 input differences by max DP (sample {SAMPLES}):");
    println!("{:>4} {:>12} {:>12} {:>10} {:>8}", "rank", "dx", "dy", "hits", "DP");
    for (i, (dp, dx, dy, hits)) in results.iter().take(10).enumerate() {
        println!(
            "{:>4} {:>12} {:>12} {:>10} {:>8.2e}",
            i + 1,
            format!("{dx:08x}"),
            format!("{dy:08x}"),
            hits,
            dp
        );
    }

    let ideal = 1.0 / SAMPLES as f64;
    let top = results[0].0;
    println!("\nideal-chance DP at this sample size: {ideal:.2e}");
    println!("top observed DP:                     {top:.2e}");
    if top > 8.0 * ideal {
        println!("VERDICT: suspicious concentration — investigate");
    } else {
        println!("VERDICT: within chance range — no exploitable differential found in F");
    }
}
