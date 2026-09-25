//! Structured linear probe for the experimental v0.2 round function.
//!
//! It scans single-bit masks plus the old v0.1 kernel masks. This is still a
//! sampled screening tool, not a LAT or a proof of linear security.
//!
//! Run: cargo run --release --example v2_linear

use riak::v2::round_function;

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

fn parity(x: u32, mask: u32) -> u32 {
    (x & mask).count_ones() & 1
}

fn main() {
    const TRIALS: u32 = 1 << 16;
    const KEY: u32 = 0x1357_9BDF;
    const CONST: u32 = 29;
    let mut rng = Rng(0x1111_2222_3333_4444);

    let mut masks = Vec::new();
    for bit in 0..32u32 {
        masks.push(1u32 << bit);
    }
    masks.extend([0x3333_3333, 0x5555_5555, 0x9999_9999]);
    masks.sort_unstable();
    masks.dedup();

    let mut best = (0.0f64, 0u32, 0u32);
    for &input_mask in &masks {
        for &output_mask in &masks {
            let mut zero = 0u32;
            for _ in 0..TRIALS {
                let x = rng.word();
                let y = round_function(x, KEY, CONST);
                zero += (parity(x, input_mask) == parity(y, output_mask)) as u32;
            }
            let bias = (zero as f64 / TRIALS as f64 - 0.5).abs();
            if bias > best.0 {
                best = (bias, input_mask, output_mask);
            }
        }
    }

    println!("v0.2 structured linear screen");
    println!("  masks={} trials={} per pair", masks.len(), TRIALS);
    println!(
        "  max_abs_bias={:.6} input={:08x} output={:08x}",
        best.0, best.1, best.2
    );
    println!("  This is not a security bound; structured LAT search remains open.");
}
