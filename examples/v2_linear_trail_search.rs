//! Structured linear-trail search for RIAK v0.2 over a finite mask set.
//!
//! The 32-bit LAT is impossible to enumerate directly. This tool builds a
//! sampled correlation table for a structured mask subset, then uses dynamic
//! programming to find the strongest 24-round trail whose intermediate
//! masks remain inside that subset. It is a trail screen, not a full LAT or
//! a linear-hull proof.
//!
//! Run: cargo run --release --example v2_linear_trail_search [trials] [mask_limit]

use std::collections::HashMap;

const ROUNDS: usize = 24;
const KEY: u32 = 0x1357_9BDF;
const CONST: u32 = 29;
const DEFAULT_TRIALS: u32 = 1 << 16;
const DEFAULT_MASK_LIMIT: usize = 16;

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

#[inline(always)]
fn f(x: u32) -> u32 {
    let mut t = x ^ KEY;
    t = t.wrapping_add(CONST);
    t = t.wrapping_mul(0x9E37_79B9);
    t ^= t >> 7;
    t = t.rotate_left(11);
    t ^= t << 9;
    t = t.wrapping_add(0x7F4A_7C15);
    t = t.wrapping_mul(0x85EB_CA6B);
    t ^= t >> 5;
    t = t.rotate_left(7);
    t ^= t << 13;
    t = t.wrapping_add(0x1B87_3593);
    t = t.wrapping_mul(0xC2B2_AE35);
    t ^= t >> 17;
    t = t.rotate_left(19);
    t ^ (t << 15)
}

fn parity(value: u32, mask: u32) -> u32 {
    (value & mask).count_ones() & 1
}

fn mask_set(limit: usize) -> Vec<u32> {
    let mut values = vec![0, 0x3333_3333, 0x5555_5555, 0x9999_9999];
    for bit in 0..32u32 {
        values.push(1u32 << bit);
    }
    values.sort_unstable();
    values.dedup();
    values.truncate(limit);
    values
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trials = args
        .get(1)
        .map(|value| value.parse().expect("trials must be an integer"))
        .unwrap_or(DEFAULT_TRIALS);
    let mask_limit = args
        .get(2)
        .map(|value| value.parse().expect("mask limit must be an integer"))
        .unwrap_or(DEFAULT_MASK_LIMIT);
    if mask_limit < 5 {
        eprintln!("mask limit must be at least 5");
        std::process::exit(2);
    }

    let masks = mask_set(mask_limit);
    let n = masks.len();
    let mut index = HashMap::new();
    for (i, &mask) in masks.iter().enumerate() {
        index.insert(mask, i);
    }
    let mut rng = Rng(0xF111_2222_3333_4444);

    println!(
        "RIAK v0.2 structured linear trail search: {n} masks, {trials} samples/mask pair"
    );
    println!("mask set: {:08x?}", masks);

    let mut correlation = vec![vec![0.0f64; n]; n];
    for (alpha_index, &alpha) in masks.iter().enumerate() {
        for (beta_index, &beta) in masks.iter().enumerate() {
            let mut sum = 0i64;
            for _ in 0..trials {
                let x = rng.word();
                let y = f(x);
                sum += if parity(x, alpha) == parity(y, beta) {
                    1
                } else {
                    -1
                };
            }
            correlation[alpha_index][beta_index] = sum as f64 / trials as f64;
        }
    }

    let mut strongest = (0.0f64, 0usize, 0usize);
    for alpha in 0..n {
        for beta in 0..n {
            let value = correlation[alpha][beta].abs();
            if value > strongest.0 {
                strongest = (value, alpha, beta);
            }
        }
    }
    println!(
        "  strongest one-round sampled correlation={:.6} alpha={:08x} beta={:08x}",
        strongest.0, masks[strongest.1], masks[strongest.2]
    );

    // Precompute XOR indices for the finite mask set.
    let mut xor_index = vec![vec![-1i32; n]; n];
    for left in 0..n {
        for right in 0..n {
            if let Some(&result) = index.get(&(masks[left] ^ masks[right])) {
                xor_index[left][right] = result as i32;
            }
        }
    }

    let n2 = n * n;
    let n3 = n2 * n;
    let state_count = n3 * n;
    let mut dp = vec![f64::NEG_INFINITY; state_count];
    for state in 0..state_count {
        let a = state / n3;
        let b = (state / n2) % n;
        let c = (state / n) % n;
        let d = state % n;
        if a != 0 || b != 0 || c != 0 || d != 0 {
            dp[state] = 0.0;
        }
    }

    for _ in 0..ROUNDS {
        let mut next = vec![f64::NEG_INFINITY; state_count];
        for state in 0..state_count {
            let value = dp[state];
            if !value.is_finite() {
                continue;
            }
            let a = state / n3;
            let b = (state / n2) % n;
            let c = (state / n) % n;
            let d = state % n;
            for alpha in 0..n {
                let beta = a;
                let correlation_value = correlation[alpha][beta];
                if correlation_value == 0.0 {
                    continue;
                }
                let v0 = beta as i32;
                let v1 = xor_index[b][alpha];
                let v2 = xor_index[c][alpha];
                let v3 = xor_index[d][alpha];
                if v1 < 0 || v2 < 0 || v3 < 0 {
                    continue;
                }
                let next_state = v0 as usize * n3
                    + v1 as usize * n2
                    + v2 as usize * n
                    + v3 as usize;
                let candidate = value + correlation_value.abs().ln();
                if candidate > next[next_state] {
                    next[next_state] = candidate;
                }
            }
        }
        dp = next;
    }

    let (best_log2, best_state) = dp
        .iter()
        .copied()
        .enumerate()
        .filter(|(state, value)| {
            let a = state / n3;
            let b = (state / n2) % n;
            let c = (state / n) % n;
            let d = state % n;
            (a != 0 || b != 0 || c != 0 || d != 0) && value.is_finite()
        })
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(state, value)| (value / std::f64::consts::LN_2, state))
        .unwrap_or((f64::NEG_INFINITY, 0));

    let a = best_state / n3;
    let b = (best_state / n2) % n;
    let c = (best_state / n) % n;
    let d = best_state % n;
    println!(
        "  best 24-round trail in this mask subset: 2^{best_log2:.3}"
    );
    println!(
        "  final mask: {:08x} {:08x} {:08x} {:08x}",
        masks[a], masks[b], masks[c], masks[d]
    );
    println!("This is not a full LAT/linear-hull result.");
}
