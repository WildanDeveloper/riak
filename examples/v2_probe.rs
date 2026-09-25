//! Initial empirical probes for the experimental RIAK v0.2 candidate.
//!
//! This is deliberately a research tool, not a security test. It checks:
//! - whether the old deterministic masks still hold;
//! - reduced-round linear bias with true 128-bit vector masks;
//! - sampled differential concentration for selected input differences.
//!
//! Run: cargo run --release --example v2_probe

use riak::v2::{round_function, RiakV2};
use std::collections::HashMap;

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

    fn block(&mut self) -> [u32; 4] {
        std::array::from_fn(|_| self.word())
    }
}

fn parity_word(x: u32, mask: u32) -> u32 {
    (x & mask).count_ones() & 1
}

fn parity_block(x: &[u32; 4], mask: &[u32; 4]) -> u32 {
    (0..4).map(|i| parity_word(x[i], mask[i])).sum::<u32>() & 1
}

fn main() {
    let mut rng = Rng(0xD1CE_B00C_5A5A_0002);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = RiakV2::from_words(key);

    println!("RIAK v0.2 candidate probe");
    println!("(research only; no security conclusion)\n");

    println!("old deterministic masks on full 24 rounds:");
    for mask in [0x3333_3333u32, 0x5555_5555, 0x9999_9999] {
        let mut violations = 0usize;
        for _ in 0..20_000 {
            let block = rng.block();
            let mut encrypted = block;
            cipher.encrypt_block(&mut encrypted);
            let input_parity = parity_word(block[1], mask);
            let output_parity = parity_word(encrypted[1], mask);
            violations += (input_parity != output_parity) as usize;
        }
        println!("  mask={mask:08x} violations={violations}/20000");
    }

    println!("\nreduced-round linear probe (true vector masks):");
    const LINEAR_TRIALS: usize = 1 << 16;
    const LINEAR_PAIRS: usize = 16;
    for rounds in [2usize, 4, 6, 8, 12, 24] {
        let mut max_bias = 0.0f64;
        for _ in 0..LINEAR_PAIRS {
            let input_mask: [u32; 4] = std::array::from_fn(|_| rng.word());
            let output_mask: [u32; 4] = std::array::from_fn(|_| rng.word());
            let mut zero = 0u32;
            for _ in 0..LINEAR_TRIALS {
                let mut block = rng.block();
                let before = parity_block(&block, &input_mask);
                cipher.encrypt_block_rounds(&mut block, rounds);
                let after = parity_block(&block, &output_mask);
                zero += (before == after) as u32;
            }
            let bias = (zero as f64 / LINEAR_TRIALS as f64 - 0.5).abs();
            max_bias = max_bias.max(bias);
        }
        println!("  rounds={rounds:>2} max_abs_bias={max_bias:.6}");
    }

    println!("\nsampled F differential probe:");
    const DDT_TRIALS: usize = 1 << 20;
    for dx in [
        0x0000_0001u32,
        0x8000_0000,
        0x4000_0000,
        0xe5d5_ffde,
        0x4636_2400,
    ] {
        let mut counts = HashMap::new();
        for _ in 0..DDT_TRIALS {
            let x = rng.word();
            let dy = round_function(x, 0xA5A5_5A5A, 17)
                ^ round_function(x ^ dx, 0xA5A5_5A5A, 17);
            *counts.entry(dy).or_insert(0u32) += 1;
        }
        let (dy, hits) = counts.iter().max_by_key(|(_, count)| **count).unwrap();
        println!(
            "  dx={dx:08x} top_dy={dy:08x} hits={hits:>7} dp={:.3e}",
            *hits as f64 / DDT_TRIALS as f64
        );
    }
}
