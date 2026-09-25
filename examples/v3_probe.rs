//! Structural and empirical probes for the RIAK v0.3 full-diffusion network.
//!
//! This tool samples structured linear/differential behavior after a small
//! structural setup. It is not a security proof.

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

    fn block(&mut self) -> [u32; 4] {
        std::array::from_fn(|_| self.word())
    }
}

fn parity(value: u32, mask: u32) -> u32 {
    (value & mask).count_ones() & 1
}

fn parity_block(block: &[u32; 4], mask: &[u32; 4]) -> u32 {
    (0..4)
        .map(|i| parity(block[i], mask[i]))
        .sum::<u32>()
        & 1
}

fn main() {
    let mut rng = Rng(0xD1CE_D1FF_1234_5679);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = RiakV3::from_words(key);

    println!("RIAK v0.3 probe (research only)");

    let mut masks = Vec::new();
    for bit in [0u32, 7, 15, 31] {
        for branch in 0..4usize {
            let mut mask = [0u32; 4];
            mask[branch] = 1u32 << bit;
            masks.push(mask);
        }
    }
    for &mask in &[0x3333_3333u32, 0x5555_5555, 0x9999_9999] {
        for branch in 0..4usize {
            let mut value = [0u32; 4];
            value[branch] = mask;
            masks.push(value);
        }
    }

    let trials = 1u32 << 11;
    for rounds in [1usize, 2, 4, 8, 24] {
        let mut best = (0.0f64, [0u32; 4], [0u32; 4]);
        for input_mask in &masks {
            for output_mask in &masks {
                let mut zero = 0u32;
                for _ in 0..trials {
                    let mut block = rng.block();
                    let before = parity_block(&block, input_mask);
                    cipher.encrypt_block_rounds(&mut block, rounds);
                    let after = parity_block(&block, output_mask);
                    zero += (before == after) as u32;
                }
                let bias = (zero as f64 / trials as f64 - 0.5).abs();
                if bias > best.0 {
                    best = (bias, *input_mask, *output_mask);
                }
            }
        }
        println!(
            "  rounds={rounds:>2} max_structured_abs_bias={:.6} input={:08x?} output={:08x?}",
            best.0, best.1, best.2
        );
    }

    let differences = [[1u32, 0, 0, 0], [0, 0, 0, 0x8000_0000], [0xffff_ffff; 4]];
    for delta in differences {
        let mut counts = std::collections::HashMap::new();
        for _ in 0..(1u32 << 14) {
            let first = rng.block();
            let mut second = first;
            for i in 0..4 {
                second[i] ^= delta[i];
            }
            let mut a = first;
            let mut b = second;
            cipher.encrypt_block(&mut a);
            cipher.encrypt_block(&mut b);
            let output = [
                a[0] ^ b[0],
                a[1] ^ b[1],
                a[2] ^ b[2],
                a[3] ^ b[3],
            ];
            *counts.entry(output).or_insert(0u32) += 1;
        }
        let (top, hits) = counts.iter().max_by_key(|(_, count)| **count).unwrap();
        println!(
            "  differential delta={delta:08x?} top={:08x?} hits={hits}",
            top
        );
    }

    println!("Sampling is not a proof of linear or differential security.");
}
