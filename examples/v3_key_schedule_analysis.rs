//! Related-key and domain-separation screen for the v0.3 key schedule.
//! Run: cargo run --release --example v3_key_schedule_analysis [cases]
//!
//! This measures schedule/output differences and a small linear screen. It is
//! not a related-key security proof.

use riak::v2::round_function;
use riak::v3::RiakV3;

const ROUNDS: usize = 24;
const DOMAIN_RACIK: u32 = 0x5241_4349;
const DOMAIN_MAC: u32 = 0x4D41_4349;
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

    fn key(&mut self) -> [u32; 16] {
        std::array::from_fn(|_| self.word())
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

fn schedule(key: [u32; 16], domain: u32) -> [u32; ROUNDS] {
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
            state[index] ^= round_function(mixed, domain, constant);
        }
        result[round] = extract_round_key(&state, round, domain);
    }
    result
}

fn parity(value: u32, mask: u32) -> u32 {
    (value & mask).count_ones() & 1
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cases: usize = args
        .get(1)
        .map(|value| value.parse().expect("cases must be an integer"))
        .unwrap_or(4096);
    let mut rng = Rng(0xA11C_E5E1_1234_5679);
    let mut total_round_difference = 0u64;
    let mut minimum_round_difference = 32u32;
    let mut maximum_round_difference = 0u32;
    let mut zero_round_differences = 0usize;
    let mut total_output_difference = 0u64;
    let mut minimum_output_difference = 128u32;
    let mut zero_output_differences = 0usize;

    for _ in 0..cases {
        let key = rng.key();
        let mut changed = key;
        let word = (rng.word() as usize) % 16;
        let bit = rng.word() % 32;
        changed[word] ^= 1u32 << bit;
        let first = schedule(key, 0);
        let second = schedule(changed, 0);
        for round in 0..ROUNDS {
            let difference = (first[round] ^ second[round]).count_ones();
            total_round_difference += u64::from(difference);
            minimum_round_difference = minimum_round_difference.min(difference);
            maximum_round_difference = maximum_round_difference.max(difference);
            zero_round_differences += (difference == 0) as usize;
        }

        // Measure the actual full v0.3 block output under the related key.
        let first_cipher = RiakV3::from_words(key);
        let second_cipher = RiakV3::from_words(changed);
        let mut block: [u32; 4] = std::array::from_fn(|_| rng.word());
        let mut other = block;
        first_cipher.encrypt_block(&mut block);
        second_cipher.encrypt_block(&mut other);
        let difference = (0..4)
            .map(|j| (block[j] ^ other[j]).count_ones())
            .sum::<u32>();
        total_output_difference += u64::from(difference);
        minimum_output_difference = minimum_output_difference.min(difference);
        zero_output_differences += (difference == 0) as usize;
    }

    println!("RIAK v0.3 key-schedule related-key screen: cases={cases}");
    println!(
        "  one-bit key change: average_round_hamming={:.3} min={minimum_round_difference} max={maximum_round_difference} zero_cells={zero_round_differences}",
        total_round_difference as f64 / (cases * ROUNDS) as f64
    );
    println!(
        "  actual related-key block output: average_hamming={:.3} min={minimum_output_difference} zero={zero_output_differences}",
        total_output_difference as f64 / cases as f64
    );

    let key = rng.key();
    let default = schedule(key, 0);
    let racik = schedule(key, DOMAIN_RACIK);
    let mac = schedule(key, DOMAIN_MAC);
    let mut domain_min = 32u32;
    let mut domain_total = 0u64;
    for round in 0..ROUNDS {
        let a = (default[round] ^ racik[round]).count_ones();
        let b = (default[round] ^ mac[round]).count_ones();
        domain_min = domain_min.min(a).min(b);
        domain_total += u64::from(a + b);
    }
    println!(
        "  domain separation: average_hamming={:.3} min={domain_min}",
        domain_total as f64 / (ROUNDS * 2) as f64
    );

    // Small related-key linear screen: one-bit key perturbations, fixed
    // single-bit key/round-key masks, and random base keys.
    const LINEAR_CASES: usize = 4096;
    let mut max_bias = 0.0f64;
    for bit in 0..32u32 {
        let key_mask = 1u32 << bit;
        for round in [0usize, 1, 12, 23] {
            let output_mask = 1u32 << ((bit + (round as u32) * 7) % 32);
            let mut equal = 0u32;
            for _ in 0..LINEAR_CASES {
                let base = rng.key();
                let mut related = base;
                related[0] ^= key_mask;
                let a = schedule(base, 0);
                let b = schedule(related, 0);
                let input_difference = parity(base[0] ^ related[0], key_mask);
                let output_difference = parity(a[round] ^ b[round], output_mask);
                equal += (input_difference == output_difference) as u32;
            }
            let bias = (equal as f64 / LINEAR_CASES as f64 - 0.5).abs();
            max_bias = max_bias.max(bias);
        }
    }
    println!("  related-key linear screen max_abs_bias={max_bias:.6}");

    let mut structured_min = 32u32;
    let mut structured_zero_cells = 0u64;
    let mut structured_total = 0u64;
    let mut structured_cases = 0u64;
    for delta in [1u32, 0x8000_0000, 0xffff_ffff, 0x3333_3333, 0x5555_5555, 0x9999_9999] {
        for word in [0usize, 1, 5, 11, 15] {
            for _ in 0..256 {
                let base = rng.key();
                let mut related = base;
                related[word] ^= delta;
                let first = schedule(base, 0);
                let second = schedule(related, 0);
                for round in 0..ROUNDS {
                    let difference = (first[round] ^ second[round]).count_ones();
                    structured_min = structured_min.min(difference);
                    structured_zero_cells += (difference == 0) as u64;
                    structured_total += u64::from(difference);
                    structured_cases += 1;
                }
            }
        }
    }
    println!(
        "  structured related-key schedule: average_hamming={:.3} min={structured_min} zero_cells={structured_zero_cells}/{}",
        structured_total as f64 / structured_cases as f64,
        structured_cases
    );
    println!("These measurements are smoke screens, not security bounds.");
}
