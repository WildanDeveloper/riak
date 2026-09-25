//! Structured linear-trail search for the RIAK v0.3 outer network.
//!
//! The 128-bit LAT is too large to enumerate. This tool samples F's
//! correlations for a finite mask set, then applies the exact sequential
//! full-diffusion mask transition for all 4*24 sub-updates. It is a bounded
//! trail screen, not a full LAT or a linear-hull proof.
//!
//! Run: cargo run --release --example v3_linear_trail_search [trials] [mask_limit]

use riak::v2::round_function;
use std::collections::HashMap;

const ROUNDS: usize = 24;
const SUBUPDATES: usize = 4;
const DEFAULT_TRIALS: u32 = 1 << 15;
const DEFAULT_MASK_LIMIT: usize = 16;
const SLOT_CONSTANTS: [u32; 4] = [
    0x0000_0000,
    0x1357_9BDF,
    0x2468_ACE0,
    0xFEDC_BA98,
];
const EXTRACTION_SEED: u32 = 0x9E37_79B9;
const EXTRACTION_TAG: u32 = 0x1357_9BDF;
const PRIMES: [u32; ROUNDS] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
];

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

fn extract_round_key(state: &[u32; 16], round: usize) -> u32 {
    let mut accumulator = PRIMES[round].wrapping_mul(EXTRACTION_SEED);
    for index in 0..16usize {
        let step = (index as u32).wrapping_mul(0x0100_0193);
        let constant = PRIMES[round]
            ^ SLOT_CONSTANTS[index & 3]
            ^ step
            ^ EXTRACTION_TAG;
        accumulator = round_function(accumulator ^ state[index], step, constant);
    }
    accumulator
}

fn key_schedule(key: [u32; 16]) -> [u32; ROUNDS] {
    let mut state = key;
    let mut result = [0u32; ROUNDS];
    for round in 0..ROUNDS {
        for index in 0..16usize {
            let mixed = state[(index + 3) & 15]
                ^ state[(index + 7) & 15].rotate_left(11)
                ^ state[(index + 13) & 15].rotate_left(5);
            let constant = PRIMES[round]
                ^ SLOT_CONSTANTS[index & 3]
                ^ (index as u32).wrapping_mul(0x0100_0193);
            state[index] ^= round_function(mixed, 0, constant);
        }
        result[round] = extract_round_key(&state, round);
    }
    result
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
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let round_keys = key_schedule(key);

    println!(
        "RIAK v0.3 structured linear trail search: {n} masks, {trials} samples/mask pair/slot"
    );
    println!("mask set: {:08x?}", masks);

    // correlation[slot][round][alpha][beta], where slot identifies one of
    // the four F calls in an outer round. Keeping round-specific cells avoids
    // averaging away a strong constant-dependent approximation.
    let mut correlation = vec![vec![vec![vec![0.0f64; n]; n]; ROUNDS]; SUBUPDATES];
    for slot in 0..SUBUPDATES {
        for round in 0..ROUNDS {
            let c = PRIMES[round] ^ SLOT_CONSTANTS[slot];
            for alpha in 0..n {
                for beta in 0..n {
                    let mut sum = 0i64;
                    for _ in 0..trials {
                        let x = rng.word();
                        let y = round_function(x, round_keys[round], c);
                        sum += if parity(x, masks[alpha]) == parity(y, masks[beta]) {
                            1
                        } else {
                            -1
                        };
                    }
                    correlation[slot][round][alpha][beta] = sum as f64 / trials as f64;
                }
            }
        }
    }

    let mut strongest = (0.0f64, 0usize, 0usize, 0usize, 0usize);
    let mut strongest_nontrivial = (0.0f64, 0usize, 0usize, 0usize, 0usize);
    for slot in 0..SUBUPDATES {
        for round in 0..ROUNDS {
            for alpha in 0..n {
                for beta in 0..n {
                    let value = correlation[slot][round][alpha][beta].abs();
                    if value > strongest.0 {
                        strongest = (value, slot, round, alpha, beta);
                    }
                    if (alpha != 0 || beta != 0) && value > strongest_nontrivial.0 {
                        strongest_nontrivial = (value, slot, round, alpha, beta);
                    }
                }
            }
        }
    }
    println!(
        "  strongest one-round sampled correlation={:.6} slot={} round={} alpha={:08x} beta={:08x}",
        strongest.0,
        strongest.1,
        strongest.2,
        masks[strongest.3],
        masks[strongest.4]
    );
    println!(
        "  strongest nontrivial sampled correlation={:.6} slot={} round={} alpha={:08x} beta={:08x}",
        strongest_nontrivial.0,
        strongest_nontrivial.1,
        strongest_nontrivial.2,
        masks[strongest_nontrivial.3],
        masks[strongest_nontrivial.4]
    );

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
    let total_steps = ROUNDS * SUBUPDATES;
    let trace = n <= 16;
    let mut parents = if trace {
        vec![vec![u32::MAX; state_count]; total_steps]
    } else {
        Vec::new()
    };
    let mut alpha_marks = if trace {
        vec![vec![0u8; state_count]; total_steps]
    } else {
        Vec::new()
    };
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

    for step in 0..(ROUNDS * SUBUPDATES) {
        let round = step / SUBUPDATES;
        let slot = step % SUBUPDATES;
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
            let branch = [a, b, c, d];
            let beta = branch[slot];
            for alpha in 0..n {
                let corr = correlation[slot][round][alpha][beta];
                if corr == 0.0 {
                    continue;
                }
                let mut next_branch = [0i32; 4];
                let mut valid = true;
                for j in 0..4 {
                    next_branch[j] = if j == slot {
                        beta as i32
                    } else {
                        xor_index[branch[j]][alpha]
                    };
                    if next_branch[j] < 0 {
                        valid = false;
                        break;
                    }
                }
                if !valid {
                    continue;
                }
                let next_state = next_branch[0] as usize * n3
                    + next_branch[1] as usize * n2
                    + next_branch[2] as usize * n
                    + next_branch[3] as usize;
                let candidate = value + corr.abs().ln();
                if candidate > next[next_state] {
                    next[next_state] = candidate;
                    if trace {
                        parents[step][next_state] = state as u32;
                        alpha_marks[step][next_state] = alpha as u8;
                    }
                }
            }
        }
        dp = next;
    }

    let (best_log, best_state) = dp
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
    println!("  best 24-round trail in this mask subset: 2^{best_log:.3}");
    println!(
        "  final mask: {:08x} {:08x} {:08x} {:08x}",
        masks[a], masks[b], masks[c], masks[d]
    );
    if trace {
        let mut current = best_state;
        let mut path = Vec::with_capacity(total_steps);
        for step in (0..total_steps).rev() {
            let parent = parents[step][current] as usize;
            let alpha = alpha_marks[step][current] as usize;
            path.push((step, parent, current, alpha));
            current = parent;
        }
        path.reverse();
        let mut nontrivial = 0usize;
        let mut printed = 0usize;
        for (step, before, after, alpha) in path {
            let slot = step % SUBUPDATES;
            let before_a = before / n3;
            let before_b = (before / n2) % n;
            let before_c = (before / n) % n;
            let before_d = before % n;
            let after_a = after / n3;
            let after_b = (after / n2) % n;
            let after_c = (after / n) % n;
            let after_d = after % n;
            let beta = [before_a, before_b, before_c, before_d][slot];
            let corr = correlation[slot][step / SUBUPDATES][alpha][beta];
            if alpha != 0 || beta != 0 {
                nontrivial += 1;
                if printed < 20 {
                    println!(
                        "  transition step={step:>2} slot={slot} corr={corr:.6} alpha={:08x} beta={:08x} before={:08x?}{:08x?}{:08x?}{:08x?} after={:08x?}{:08x?}{:08x?}{:08x?}",
                        masks[alpha],
                        masks[beta],
                        masks[before_a],
                        masks[before_b],
                        masks[before_c],
                        masks[before_d],
                        masks[after_a],
                        masks[after_b],
                        masks[after_c],
                        masks[after_d]
                    );
                    printed += 1;
                }
            }
        }
        println!("  trace nontrivial subupdates={nontrivial}/{total_steps}");
    }
    println!("This is not a full LAT/linear-hull result.");
}
