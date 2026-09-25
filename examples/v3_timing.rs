//! Rough timing smoke test for the v0.3 block cipher.
//!
//! This is not dudect/ctgrind and cannot prove constant-time behavior. It
//! checks whether a fixed input class and a random input class have a large
//! obvious timing separation on this host.

use riak::v3::RiakV3;
use std::time::Instant;

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

fn main() {
    const BATCHES: usize = 2_000;
    const PER_BATCH: usize = 32;
    let key = [0x1234_5678u32; 16];
    let cipher = RiakV3::from_words(key);
    let fixed = [0x0123_4567u32, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210];
    let mut rng = Rng(0xD1CE_D1FF_1234_5679);

    let start = Instant::now();
    for _ in 0..BATCHES {
        for _ in 0..PER_BATCH {
            let mut block = fixed;
            cipher.encrypt_block(&mut block);
            std::hint::black_box(block);
        }
    }
    let fixed_seconds = start.elapsed().as_secs_f64();

    let start = Instant::now();
    for _ in 0..BATCHES {
        for _ in 0..PER_BATCH {
            let mut block: [u32; 4] = std::array::from_fn(|_| rng.word());
            cipher.encrypt_block(&mut block);
            std::hint::black_box(block);
        }
    }
    let random_seconds = start.elapsed().as_secs_f64();

    let fixed_ns = fixed_seconds * 1e9 / (BATCHES * PER_BATCH) as f64;
    let random_ns = random_seconds * 1e9 / (BATCHES * PER_BATCH) as f64;
    println!("RIAK v0.3 rough timing smoke test");
    println!("  fixed_input_ns/block={fixed_ns:.2}");
    println!("  random_input_ns/block={random_ns:.2}");
    println!("  difference_ns/block={:.2}", random_ns - fixed_ns);
    println!("No timing conclusion is valid without a statistical leakage tool.");
}
