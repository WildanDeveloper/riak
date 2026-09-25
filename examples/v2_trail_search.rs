//! Structured differential-trail screen for RIAK v0.2.
//!
//! The DDT values are sampled, so this is a search over a measured candidate
//! family, not a proof of a differential bound. It does use exact GF(2)
//! feasibility for the selected per-round output differences.
//!
//! Run: cargo run --release --example v2_trail_search [samples] [budget] [candidate_limit]

use std::collections::HashMap;

const ROUNDS: usize = 24;
const TOP: u32 = 0x8000_0000;
const DEFAULT_SAMPLES: u32 = 1 << 18;
const DEFAULT_BUDGET: u64 = 10_000_000;
const KEY: u32 = 0xA5A5_5A5A;
const CONST: u32 = 17;

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

fn candidate_deltas() -> Vec<u32> {
    let mut values = vec![TOP];
    for i in 0..31u32 {
        values.push(TOP | (1 << i));
    }
    for i in 0..31u32 {
        for j in (i + 1)..31u32 {
            values.push(TOP | (1 << i) | (1 << j));
        }
    }
    values
}

fn measure(dx: u32, samples: u32, rng: &mut Rng) -> (u32, f64) {
    let mut counts = HashMap::new();
    for _ in 0..samples {
        let x = rng.word();
        let dy = f(x) ^ f(x ^ dx);
        *counts.entry(dy).or_insert(0u32) += 1;
    }
    let (dy, hits) = counts.iter().max_by_key(|(_, count)| **count).unwrap();
    (*dy, *hits as f64 / samples as f64)
}

#[derive(Clone, Copy)]
struct Word {
    coefficients: [u8; 4],
    constant: u32,
}

impl Word {
    fn base(index: usize) -> Self {
        let mut coefficients = [0u8; 4];
        coefficients[index] = 1;
        Self {
            coefficients,
            constant: 0,
        }
    }

    fn xor(self, other: Self) -> Self {
        let mut coefficients = [0u8; 4];
        for i in 0..4 {
            coefficients[i] = self.coefficients[i] ^ other.coefficients[i];
        }
        Self {
            coefficients,
            constant: self.constant ^ other.constant,
        }
    }
}

type Bits = Vec<[[u8; 5]; 4]>;

fn new_bits() -> Bits {
    vec![[[0; 5]; 4]; 32]
}

fn add_equation(bits: &mut Bits, bit: usize, coefficients: &[u8; 4], rhs: u8) -> bool {
    let mut row = [0u8; 5];
    row[..4].copy_from_slice(coefficients);
    row[4] = rhs;

    for pivot in 0..4 {
        if row[pivot] == 1 {
            if bits[bit][pivot] == [0; 5] {
                bits[bit][pivot] = row;
                return true;
            }
            for i in 0..5 {
                row[i] ^= bits[bit][pivot][i];
            }
        }
    }
    row[4] == 0
}

fn rank4(rows: &[u8]) -> usize {
    let mut basis = [0u8; 4];
    let mut rank = 0;
    for &row in rows {
        let mut value = row;
        while value != 0 {
            let pivot = value.trailing_zeros() as usize;
            if basis[pivot] == 0 {
                basis[pivot] = value;
                rank += 1;
                break;
            }
            value ^= basis[pivot];
        }
    }
    rank
}

fn pack_coefficients(coefficients: &[u8; 4]) -> u8 {
    coefficients[0]
        | (coefficients[1] << 2)
        | (coefficients[2] << 4)
        | (coefficients[3] << 6)
}

struct Search {
    best_log2_dp: f64,
    best_trail: Vec<(usize, u32, u32, f64)>,
    trail: Vec<(usize, u32, u32, f64)>,
    candidates: Vec<(u32, u32, f64)>,
    nodes: u64,
    budget: u64,
    aborted: bool,
}

impl Search {
    fn dfs(
        &mut self,
        words: &[Word; 4],
        round: usize,
        log2_dp: f64,
        bits: &Bits,
        homogeneous_constraints: &[u8],
    ) {
        if self.aborted || (self.best_log2_dp > -900.0 && log2_dp <= self.best_log2_dp) {
            return;
        }
        self.nodes += 1;
        if self.nodes > self.budget {
            self.aborted = true;
            return;
        }
        if round == ROUNDS {
            if !self.trail.is_empty()
                && rank4(homogeneous_constraints) < 4
                && log2_dp > self.best_log2_dp
            {
                self.best_log2_dp = log2_dp;
                self.best_trail = self.trail.clone();
            }
            return;
        }

        let input_difference = words[1]
            .xor(words[2])
            .xor(words[3]);

        for index in 0..self.candidates.len() {
            let (delta, eta, probability) = self.candidates[index];
            let mut branch_bits = bits.clone();
            let mut constraints = homogeneous_constraints.to_vec();
            let mut valid = true;
            for bit in 0..32 {
                let rhs = ((delta >> bit) & 1) as u8
                    ^ ((input_difference.constant >> bit) & 1) as u8;
                if !add_equation(
                    &mut branch_bits,
                    bit,
                    &input_difference.coefficients,
                    rhs,
                ) {
                    valid = false;
                    break;
                }
            }
            if valid {
                constraints.push(pack_coefficients(&input_difference.coefficients));
                let next = words[0].xor(Word {
                    coefficients: [0; 4],
                    constant: eta,
                });
                let next_words = [words[1], words[2], words[3], next];
                self.trail.push((round, delta, eta, probability));
                self.dfs(
                    &next_words,
                    round + 1,
                    log2_dp + probability.log2(),
                    &branch_bits,
                    &constraints,
                );
                self.trail.pop();
            }
        }

        // Inactive round: input difference must be zero.
        let mut branch_bits = bits.clone();
        let mut constraints = homogeneous_constraints.to_vec();
        let mut valid = true;
        for bit in 0..32 {
            let rhs = ((input_difference.constant >> bit) & 1) as u8;
            if !add_equation(
                &mut branch_bits,
                bit,
                &input_difference.coefficients,
                rhs,
            ) {
                valid = false;
                break;
            }
        }
        if valid {
            constraints.push(pack_coefficients(&input_difference.coefficients));
            let next_words = [words[1], words[2], words[3], words[0]];
            self.dfs(
                &next_words,
                round + 1,
                log2_dp,
                &branch_bits,
                &constraints,
            );
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args
        .get(1)
        .map(|value| value.parse().expect("samples must be an integer"))
        .unwrap_or(DEFAULT_SAMPLES);
    let budget = args
        .get(2)
        .map(|value| value.parse().expect("budget must be an integer"))
        .unwrap_or(DEFAULT_BUDGET);
    let candidate_limit = args
        .get(3)
        .map(|value| value.parse().expect("candidate limit must be an integer"))
        .unwrap_or(64);
    let deltas = candidate_deltas();
    let mut rng = Rng(0x5EED_5EED_5EED_0002);
    let mut candidates = Vec::with_capacity(deltas.len());

    println!(
        "RIAK v0.2 structured differential trail screen: {} deltas × {samples} samples",
        deltas.len()
    );
    for delta in deltas {
        let (eta, probability) = measure(delta, samples, &mut rng);
        candidates.push((delta, eta, probability));
    }
    candidates.sort_by(|a, b| b.2.total_cmp(&a.2));
    candidates.truncate(candidate_limit);
    println!("using {} measured candidates for DFS", candidates.len());
    println!("top measured candidates:");
    for (delta, eta, probability) in candidates.iter().take(5) {
        println!(
            "  delta={delta:08x} eta={eta:08x} dp={probability:.6} (2^{:.1})",
            probability.log2()
        );
    }

    let initial = [
        Word::base(0),
        Word::base(1),
        Word::base(2),
        Word::base(3),
    ];
    let mut search = Search {
        best_log2_dp: -999.0,
        best_trail: Vec::new(),
        trail: Vec::new(),
        candidates,
        nodes: 0,
        budget,
        aborted: false,
    };
    search.dfs(&initial, 0, 0.0, &new_bits(), &[]);

    println!("\nnodes explored: {}", search.nodes);
    if search.aborted {
        println!("budget exhausted: result is not exhaustive");
    }
    if search.best_trail.is_empty() {
        println!("no feasible sampled trail found within the search budget");
    } else {
        println!("best screened trail: 2^{:.1}", search.best_log2_dp);
        for (round, delta, eta, probability) in &search.best_trail {
            println!(
                "  round {round:>2}: delta={delta:08x} eta={eta:08x} dp={probability:.6}"
            );
        }
        if search.best_log2_dp > -128.0 {
            println!("screened trail exceeds 2^-128; redesign is required");
        } else {
            println!("screened trail is below 2^-128; this is not a proof");
        }
    }
}
