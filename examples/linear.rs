//! Linear cryptanalysis (empirical, first pass).
//!
//! Uses actual 128-bit input/output masks `[u32; 4]`. The earlier version
//! accidentally applied one mask to the XOR of all four words and could not
//! test branch-local masks such as the known v0.1 kernel.
//!
//! Run: cargo run --release --example linear [trials] [mask_pairs]

#![allow(deprecated)]

use riak::Riak;

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

fn parity_word(x: u32, mask: u32) -> u32 {
    (x & mask).count_ones() & 1
}

fn parity_block(block: &[u32; 4], mask: &[u32; 4]) -> u32 {
    (0..4)
        .map(|i| parity_word(block[i], mask[i]))
        .sum::<u32>()
        & 1
}

fn main() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_1234);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = Riak::from_words(key);

    let args: Vec<String> = std::env::args().collect();
    let trials: u64 = args
        .get(1)
        .map(|value| value.parse().expect("trials must be an integer"))
        .unwrap_or(1 << 24);
    let pairs: usize = args
        .get(2)
        .map(|value| value.parse().expect("pairs must be an integer"))
        .unwrap_or(64);

    println!(
        "{:>6} {:>12} {:>14} {:>14} {:>10}",
        "round", "pairs", "max |bias|", "expected|rand|", "verdict"
    );
    for rounds in [2usize, 3, 4, 5, 6, 8, 12, 24] {
        let mut max_bias: f64 = 0.0;
        for _ in 0..pairs {
            let input_mask: [u32; 4] = std::array::from_fn(|_| rng.word());
            let output_mask: [u32; 4] = std::array::from_fn(|_| rng.word());
            let mut zero = 0u64;

            for i in 0..trials {
                let mut block = std::array::from_fn(|_| rng.word());
                let before = parity_block(&block, &input_mask);
                cipher.encrypt_block_rounds(&mut block, rounds);
                let after = parity_block(&block, &output_mask);
                if before == after {
                    zero += 1;
                }
                std::hint::black_box(i);
            }

            let bias = (zero as f64 / trials as f64 - 0.5).abs();
            if bias > max_bias {
                max_bias = bias;
            }
        }
        let expected = (2.0f64.ln() * pairs as f64 / (2.0 * trials as f64)).sqrt();
        let verdict = if max_bias > 2.5 * expected {
            "SUSPICIOUS"
        } else {
            "random"
        };
        println!(
            "{:>6} {:>12} {:>14.6} {:>14.6} {:>10}",
            rounds, pairs, max_bias, expected, verdict
        );
    }

    println!("\nTargeted v0.1 kernel-mask regression:");
    for mask in [0x3333_3333u32, 0x5555_5555, 0x9999_9999] {
        let branch_mask = [0, mask, 0, 0];
        let mut violations = 0usize;
        for _ in 0..10_000 {
            let mut block = std::array::from_fn(|_| rng.word());
            let before = parity_block(&block, &branch_mask);
            cipher.encrypt_block(&mut block);
            let after = parity_block(&block, &branch_mask);
            violations += (before != after) as usize;
        }
        println!("  mask={mask:08x} violations={violations}/10000");
        assert_eq!(violations, 0, "known v0.1 linear break disappeared");
    }
}
