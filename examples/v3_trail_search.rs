//! Structured differential-trail search for the RIAK v0.3 outer network.
//!
//! The search uses a sampled DDT family for F and exact difference propagation
//! through all 4*24 sequential sub-updates. The initial low-weight family is
//! extended on demand when a new input difference is encountered. It is
//! deliberately a bounded measured screen, not an exhaustive differential
//! proof; the F table uses one representative key/constant.
//!
//! Run: cargo run --release --example v3_trail_search [samples] [budget] [outputs_per_input]

use riak::v2::round_function;
use std::collections::HashMap;

const STEPS: usize = 24 * 4;
const KEY: u32 = 0x1357_9BDF;
const CONST: u32 = 0x6D2B_79F5;
const DEFAULT_SAMPLES: u32 = 1 << 16;
const DEFAULT_BUDGET: u64 = 1_000_000;
const DEFAULT_OUTPUTS: usize = 8;

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

fn candidate_inputs() -> Vec<u32> {
    let mut values = vec![0x3333_3333, 0x5555_5555, 0x9999_9999];
    for bit in 0..32u32 {
        values.push(1u32 << bit);
        for other in (bit + 1)..32 {
            values.push((1u32 << bit) | (1u32 << other));
        }
    }
    values.sort_unstable();
    values.dedup();
    values
}

struct Search {
    candidates: HashMap<u32, Vec<(u32, f64)>>,
    samples: u32,
    outputs_per_input: usize,
    rng: Rng,
    best_log2_dp: f64,
    best_trail: Vec<(usize, u32, u32, f64)>,
    trail: Vec<(usize, u32, u32, f64)>,
    nodes: u64,
    budget: u64,
    aborted: bool,
}

impl Search {
    fn sample_candidates(&mut self, input_delta: u32) -> Vec<(u32, f64)> {
        if let Some(values) = self.candidates.get(&input_delta) {
            return values.clone();
        }
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for _ in 0..self.samples {
            let x = self.rng.word();
            let y = round_function(x, KEY, CONST)
                ^ round_function(x ^ input_delta, KEY, CONST);
            *counts.entry(y).or_insert(0) += 1;
        }
        let mut values: Vec<(u32, f64)> = counts
            .into_iter()
            .map(|(delta, count)| (delta, count as f64 / self.samples as f64))
            .collect();
        values.sort_by(|a, b| b.1.total_cmp(&a.1));
        values.truncate(self.outputs_per_input);
        self.candidates.insert(input_delta, values.clone());
        values
    }

    fn dfs(&mut self, state: [u32; 4], step: usize, log2_dp: f64) {
        if self.aborted
            || (self.best_log2_dp.is_finite() && log2_dp <= self.best_log2_dp)
        {
            return;
        }
        self.nodes += 1;
        if self.nodes > self.budget {
            self.aborted = true;
            return;
        }
        if step == STEPS {
            if state != [0; 4] && log2_dp > self.best_log2_dp {
                self.best_log2_dp = log2_dp;
                self.best_trail = self.trail.clone();
            }
            return;
        }

        let slot = step % 4;
        let input_delta = state
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != slot)
            .fold(0u32, |value, (_, word)| value ^ *word);
        let options = self.sample_candidates(input_delta);
        for (output_delta, probability) in options {
            let mut next = state;
            next[slot] ^= output_delta;
            if next == [0; 4] {
                continue;
            }
            self.trail.push((step, input_delta, output_delta, probability));
            self.dfs(next, step + 1, log2_dp + probability.log2());
            self.trail.pop();
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
    let outputs_per_input = args
        .get(3)
        .map(|value| value.parse().expect("outputs per input must be an integer"))
        .unwrap_or(DEFAULT_OUTPUTS);
    if samples == 0 || outputs_per_input == 0 {
        eprintln!("samples and outputs per input must be nonzero");
        std::process::exit(2);
    }

    let mut rng = Rng(0xD1CE_D1FF_1234_5679);
    let mut candidates = HashMap::new();
    let inputs = candidate_inputs();
    for &input_delta in &inputs {
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for _ in 0..samples {
            let x = rng.word();
            let y = round_function(x, KEY, CONST)
                ^ round_function(x ^ input_delta, KEY, CONST);
            *counts.entry(y).or_insert(0) += 1;
        }
        let mut values: Vec<(u32, f64)> = counts
            .into_iter()
            .map(|(delta, count)| (delta, count as f64 / samples as f64))
            .collect();
        values.sort_by(|a, b| b.1.total_cmp(&a.1));
        values.truncate(outputs_per_input);
        candidates.insert(input_delta, values);
    }
    candidates.insert(
        0,
        vec![(0, 1.0)],
    );

    let roots = [
        [1u32, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
        [0x8000_0000, 0, 0, 0],
        [0, 0, 0, 0x8000_0000],
        [0xffff_ffff, 0, 0, 0],
        [0xffff_ffff; 4],
    ];

    println!(
        "RIAK v0.3 structured differential trail screen: {} input masks, {samples} samples, {outputs_per_input} outputs/input",
        inputs.len()
    );
    let mut search = Search {
        candidates,
        samples,
        outputs_per_input,
        rng: Rng(0xA11C_E5E1_1234_5679),
        best_log2_dp: f64::NEG_INFINITY,
        best_trail: Vec::new(),
        trail: Vec::new(),
        nodes: 0,
        budget,
        aborted: false,
    };
    for root in roots {
        search.dfs(root, 0, 0.0);
    }
    println!("nodes explored: {}", search.nodes);
    if search.best_trail.is_empty() {
        println!("no feasible sampled trail found within the search budget");
    } else {
        println!("best sampled trail: 2^{:.3}", search.best_log2_dp);
        for &(step, input, output, probability) in search.best_trail.iter().take(20) {
            println!(
                "  step={step:>2} dx={input:08x} dy={output:08x} dp={:.3e}",
                probability
            );
        }
        if search.best_trail.len() > 20 {
            println!("  ... {} transitions total", search.best_trail.len());
        }
    }
    if search.aborted {
        println!("budget exhausted; result is not exhaustive");
    }
    println!("This is not a proof of differential security.");
}
