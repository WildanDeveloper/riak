//! Full-block true-vector linear screen for RIAK v0.3.
//! Run: cargo run --release --example v3_full_linear [trials]
//!
//! This samples complete 128-bit input/output masks. It is not a linear
//! security proof.

use riak::v3::RiakV3;

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

fn parity_word(value: u32, mask: u32) -> u32 {
    (value & mask).count_ones() & 1
}

fn parity_block(block: &[u32; 4], mask: &[u32; 4]) -> u32 {
    (0..4)
        .map(|i| parity_word(block[i], mask[i]))
        .sum::<u32>()
        & 1
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trials: u32 = args
        .get(1)
        .map(|value| value.parse().expect("trials must be an integer"))
        .unwrap_or(1 << 14);
    let pairs = 32usize;
    let mut rng = Rng(0xD1CE_D1FF_1234_5679);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = RiakV3::from_words(key);

    println!("RIAK v0.3 true-vector linear screen: {trials} samples/pair, {pairs} pairs");
    for rounds in [1usize, 2, 4, 8, 12, 24] {
        let mut best = (0.0f64, [0u32; 4], [0u32; 4]);
        for _ in 0..pairs {
            let input_mask: [u32; 4] = std::array::from_fn(|_| rng.word());
            let output_mask: [u32; 4] = std::array::from_fn(|_| rng.word());
            let mut zero = 0u32;
            for _ in 0..trials {
                let mut block: [u32; 4] = std::array::from_fn(|_| rng.word());
                let before = parity_block(&block, &input_mask);
                cipher.encrypt_block_rounds(&mut block, rounds);
                let after = parity_block(&block, &output_mask);
                zero += (before == after) as u32;
            }
            let bias = (zero as f64 / trials as f64 - 0.5).abs();
            if bias > best.0 {
                best = (bias, input_mask, output_mask);
            }
        }
        println!(
            "  rounds={rounds:>2} max_abs_bias={:.6} input={:08x?} output={:08x?}",
            best.0, best.1, best.2
        );
    }
    println!("This sampled screen is not a linear-hull proof.");
}
