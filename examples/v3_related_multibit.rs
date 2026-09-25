//! Bounded multi-bit and domain-crossing related-key screen for v0.3.
//!
//! Run: cargo run --release --example v3_related_multibit [cases]
//!
//! This is an exploratory screen, not a related-key security proof or a
//! key-recovery attack. The schedule model is intentionally duplicated here
//! so that the measured schedule can be compared with the block-cipher path.

use riak::v2::{round_function, PRIMES};
use riak::v3::{RiakV3, DOMAIN_DEFAULT, DOMAIN_MAC, DOMAIN_RACIK};

const ROUNDS: usize = 24;
const SLOT_CONSTANTS: [u32; 4] = [
    0x0000_0000,
    0x1357_9BDF,
    0x2468_ACE0,
    0xFEDC_BA98,
];
const EXTRACTION_SEED: u32 = 0x9E37_79B9;
const EXTRACTION_TAG: u32 = 0x1357_9BDF;

const DELTAS: [(&str, u32, bool); 8] = [
    ("one-bit", 0x0000_0001, false),
    ("two-bit same-word", 0x0000_0003, false),
    ("edge-pair cross-word", 0x8000_0001, true),
    ("adjacent-byte cross-word", 0x0101_0101, true),
    ("alternating-low cross-word", 0x5555_5555, true),
    ("alternating-high cross-word", 0xAAAA_AAAA, true),
    ("all-ones cross-word", 0xFFFF_FFFF, true),
    ("sparse-pair cross-word", 0x0001_0001, true),
];

#[derive(Clone, Copy)]
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

    fn key(&mut self) -> [u32; 16] {
        std::array::from_fn(|_| self.word())
    }
}

#[derive(Clone, Copy)]
struct Stats {
    cells: u64,
    total: u64,
    minimum: u32,
    maximum: u32,
    zeroes: u64,
    below_eight: u64,
}

impl Stats {
    fn new() -> Self {
        Self {
            cells: 0,
            total: 0,
            minimum: u32::MAX,
            maximum: 0,
            zeroes: 0,
            below_eight: 0,
        }
    }

    fn observe(&mut self, difference: u32) {
        self.cells += 1;
        self.total += u64::from(difference);
        self.minimum = self.minimum.min(difference);
        self.maximum = self.maximum.max(difference);
        self.zeroes += u64::from(difference == 0);
        self.below_eight += u64::from(difference < 8);
    }

    fn print(self, label: &str) {
        println!(
            "  {label}: average_hamming={:.3} min={} max={} zero_cells={} below_8={}",
            self.total as f64 / self.cells as f64,
            self.minimum,
            self.maximum,
            self.zeroes,
            self.below_eight
        );
    }
}

fn extract_round_key(state: &[u32; 16], round: usize, domain: u32) -> u32 {
    let mut accumulator = domain ^ PRIMES[round].wrapping_mul(EXTRACTION_SEED);
    for index in 0..16usize {
        let step = (index as u32).wrapping_mul(0x0100_0193);
        let constant = PRIMES[round]
            ^ SLOT_CONSTANTS[index & 3]
            ^ step
            ^ EXTRACTION_TAG;
        accumulator = round_function(
            accumulator ^ state[index],
            domain ^ step,
            constant,
        );
    }
    accumulator
}

fn schedule(mut key: [u32; 16], domain: u32) -> [u32; ROUNDS] {
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
            state[index] ^= round_function(mixed, domain, constant);
        }
        result[round] = extract_round_key(&state, round, domain);
    }
    for word in &mut key {
        *word = 0;
        std::hint::black_box(*word);
    }
    for word in &mut state {
        *word = 0;
        std::hint::black_box(*word);
    }
    result
}

fn hamming(left: u32, right: u32) -> u32 {
    (left ^ right).count_ones()
}

fn parity(value: u32, mask: u32) -> u32 {
    (value & mask).count_ones() & 1
}

fn make_related(
    rng: &mut Rng,
    base: [u32; 16],
    delta: u32,
    cross_word: bool,
) -> ([u32; 16], usize, usize, u32) {
    let word = (rng.word() as usize) & 15;
    let mut related = base;
    related[word] ^= delta;
    if cross_word {
        let second_word = (word + 1 + (rng.word() as usize % 14)) & 15;
        let second_delta = delta.rotate_left((rng.word() % 31) + 1);
        related[second_word] ^= second_delta;
        (related, word, second_word, second_delta)
    } else {
        (related, word, word, 0)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cases: usize = args
        .get(1)
        .map(|value| value.parse().expect("cases must be an integer"))
        .unwrap_or(4096);
    let mut rng = Rng(0x6D62_7469_6C6B_6579);

    println!(
        "RIAK v0.3 multi-bit related-key screen: cases_per_pattern={cases}"
    );
    for (name, delta, cross_word) in DELTAS {
        let mut schedule_stats = Stats::new();
        let mut output_stats = Stats::new();
        for _ in 0..cases {
            let base = rng.key();
            let (paired, _word, _second_word, _second_delta) =
                make_related(&mut rng, base, delta, cross_word);
            let first_schedule = schedule(base, DOMAIN_DEFAULT);
            let second_schedule = schedule(paired, DOMAIN_DEFAULT);
            for round in 0..ROUNDS {
                schedule_stats.observe(hamming(first_schedule[round], second_schedule[round]));
            }

            let first_cipher = RiakV3::from_words(base);
            let second_cipher = RiakV3::from_words(paired);
            for _ in 0..2 {
                let block: [u32; 4] = std::array::from_fn(|_| rng.word());
                let mut first = block;
                let mut second = block;
                first_cipher.encrypt_block(&mut first);
                second_cipher.encrypt_block(&mut second);
                output_stats.observe(
                    (0..4)
                        .map(|index| hamming(first[index], second[index]))
                        .sum(),
                );
            }
        }
        schedule_stats.print(&format!("{name} schedule"));
        output_stats.print(&format!("{name} block-output"));
    }

    let mut domain_stats = [Stats::new(), Stats::new(), Stats::new()];
    let mut domain_output = [Stats::new(), Stats::new(), Stats::new()];
    let domains = [DOMAIN_DEFAULT, DOMAIN_RACIK, DOMAIN_MAC];
    for _ in 0..cases {
        let key = rng.key();
        let schedules = [
            schedule(key, domains[0]),
            schedule(key, domains[1]),
            schedule(key, domains[2]),
        ];
        for left in 0..3usize {
            for right in left + 1..3usize {
                let pair_index = match (left, right) {
                    (0, 1) => 0,
                    (0, 2) => 1,
                    _ => 2,
                };
                for round in 0..ROUNDS {
                    domain_stats[pair_index]
                        .observe(hamming(schedules[left][round], schedules[right][round]));
                }
                let left_cipher = RiakV3::from_words_with_domain(key, domains[left]);
                let right_cipher = RiakV3::from_words_with_domain(key, domains[right]);
                let mut first: [u32; 4] = std::array::from_fn(|_| rng.word());
                let mut second = first;
                left_cipher.encrypt_block(&mut first);
                right_cipher.encrypt_block(&mut second);
                domain_output[pair_index].observe(
                    (0..4)
                        .map(|index| hamming(first[index], second[index]))
                        .sum(),
                );
            }
        }
    }
    println!("domain crossing (same key, distinct public domains):");
    for (index, label) in ["default/RACIK", "default/MAC", "RACIK/MAC"]
        .iter()
        .enumerate()
    {
        domain_stats[index].print(&format!("{label} schedule"));
        domain_output[index].print(&format!("{label} block-output"));
    }

    const LINEAR_CASES: usize = 512;
    let mut max_bias = 0.0f64;
    for (_, delta, cross_word) in DELTAS {
        for round in [0usize, 1, 12, 23] {
            let output_mask = 1u32 << ((round as u32 * 9 + 3) & 31);
            let mut equal = 0u32;
            for _ in 0..LINEAR_CASES {
                let base = rng.key();
                let (related, word, second_word, second_delta) =
                    make_related(&mut rng, base, delta, cross_word);
                let first_schedule = schedule(base, DOMAIN_DEFAULT);
                let second_schedule = schedule(related, DOMAIN_DEFAULT);
                let input_difference = parity(base[word] ^ related[word], delta)
                    ^ parity(base[second_word] ^ related[second_word], second_delta);
                let output_difference =
                    parity(first_schedule[round] ^ second_schedule[round], output_mask);
                equal += u32::from(input_difference == output_difference);
            }
            let bias = (equal as f64 / LINEAR_CASES as f64 - 0.5).abs();
            max_bias = max_bias.max(bias);
        }
    }
    println!("  related-key linear screen max_abs_bias={max_bias:.6}");
    println!("This bounded screen is not a proof and does not recover a key.");
}
