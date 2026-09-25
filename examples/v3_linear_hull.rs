//! Bounded linear-hull screen for the RIAK v0.3 outer network.
//!
//! For a finite mask set, this sums signed sampled F correlations along every
//! 4*24-subupdate path from selected input masks. It is a small hull search,
//! not a full 128-bit LAT or a proof of linear security.
//!
//! Run: cargo run --release --example v3_linear_hull [trials] [mask_limit] [input_count]

use riak::v2::round_function;
use std::collections::HashMap;

const ROUNDS: usize = 24;
const SUBUPDATES: usize = 4;
const DEFAULT_TRIALS: u32 = 1 << 12;
const DEFAULT_MASK_LIMIT: usize = 12;
const DEFAULT_INPUTS: usize = 8;
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
    // A closed GF(2) subspace is used here so every XOR transition remains
    // inside the searched family. `limit` selects a 3- or 4-dimensional
    // subspace; arbitrary truncation would make the result mostly a dead-end
    // path artifact.
    let dimension = if limit >= 16 { 4 } else { 3 };
    let basis = [0x0000_0001u32, 0x0000_0080, 0x0000_8000, 0x8000_0000];
    let mut values = Vec::with_capacity(1 << dimension);
    for combination in 0..(1u32 << dimension) {
        let mut value = 0u32;
        for bit in 0..dimension {
            if (combination >> bit) & 1 != 0 {
                value ^= basis[bit];
            }
        }
        values.push(value);
    }
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
                ^ (index as u32).wrapping_mul(0x01000193);
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
    let input_count = args
        .get(3)
        .map(|value| value.parse().expect("input count must be an integer"))
        .unwrap_or(DEFAULT_INPUTS);
    if mask_limit < 8 || input_count == 0 {
        eprintln!("mask limit must be >=8 and input count must be nonzero");
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
    let mut inputs = Vec::new();
    for branch in 0..4usize {
        for mask in 1..n {
            let mut state = [0usize; 4];
            state[branch] = mask;
            inputs.push(state);
            if inputs.len() >= input_count {
                break;
            }
        }
        if inputs.len() >= input_count {
            break;
        }
    }

    println!("RIAK v0.3 bounded linear-hull screen");
    println!("  masks={n} trials={trials} input_masks={}", inputs.len());
    println!("  mask set: {:08x?}", masks);

    for input in inputs {
        let mut dp = vec![0.0f64; state_count];
        let input_state = input[0] * n3 + input[1] * n2 + input[2] * n + input[3];
        dp[input_state] = 1.0;
        for step in 0..(ROUNDS * SUBUPDATES) {
            let round = step / SUBUPDATES;
            let slot = step % SUBUPDATES;
            let mut next = vec![0.0f64; state_count];
            for state in 0..state_count {
                let value = dp[state];
                if value == 0.0 {
                    continue;
                }
                let branch = [
                    state / n3,
                    (state / n2) % n,
                    (state / n) % n,
                    state % n,
                ];
                let beta = branch[slot];
                for alpha in 0..n {
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
                    next[next_state] += value * correlation[slot][round][alpha][beta];
                }
            }
            dp = next;
        }
        let (output, hull) = dp
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
            .max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))
            .map(|(state, value)| (state, value.abs()))
            .unwrap_or((0, 0.0));
        let a = output / n3;
        let b = (output / n2) % n;
        let c = (output / n) % n;
        let d = output % n;
        let log2_hull = if hull > 0.0 {
            hull.log2()
        } else {
            f64::NEG_INFINITY
        };
        println!(
            "  input={:08x?}{:08x?}{:08x?}{:08x?} max_abs_hull={:.6e} log2={log2_hull:.3} output={:08x?}{:08x?}{:08x?}{:08x?}",
            masks[input[0]], masks[input[1]], masks[input[2]], masks[input[3]], hull,
            masks[a], masks[b], masks[c], masks[d]
        );
    }
    println!("This is a bounded sampled hull screen, not a proof.");
}
