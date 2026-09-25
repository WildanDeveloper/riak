//! Avalanche/diffusion smoke screen for RIAK v0.3.
//! Run: cargo run --release --example v3_avalanche [cases]
//! This is a statistical sanity check, not a security proof.

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cases: usize = args
        .get(1)
        .map(|value| value.parse().expect("cases must be an integer"))
        .unwrap_or(512);
    let mut rng = Rng(0xD1CE_D1FF_1234_5679);

    println!("RIAK v0.3 avalanche smoke screen: cases={cases}");
    for rounds in [1usize, 4, 8, 24] {
        let mut plaintext_total = 0u64;
        let mut plaintext_min = 128u32;
        let mut plaintext_max = 0u32;
        let mut key_total = 0u64;
        let mut key_min = 128u32;
        let mut key_max = 0u32;
        for _ in 0..cases {
            let key: [u32; 16] = std::array::from_fn(|_| rng.word());
            let mut changed_key = key;
            changed_key[(rng.word() as usize) % 16] ^= 1u32 << (rng.word() % 32);
            let first = RiakV3::from_words(key);
            let second = RiakV3::from_words(changed_key);
            let plaintext: [u32; 4] = std::array::from_fn(|_| rng.word());
            let mut changed_plaintext = plaintext;
            changed_plaintext[(rng.word() as usize) % 4] ^=
                1u32 << (rng.word() % 32);

            let mut a = plaintext;
            let mut b = changed_plaintext;
            first.encrypt_block_rounds(&mut a, rounds);
            first.encrypt_block_rounds(&mut b, rounds);
            let difference = a
                .iter()
                .zip(b.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum::<u32>();
            plaintext_total += u64::from(difference);
            plaintext_min = plaintext_min.min(difference);
            plaintext_max = plaintext_max.max(difference);

            let mut a = plaintext;
            let mut b = plaintext;
            first.encrypt_block_rounds(&mut a, rounds);
            second.encrypt_block_rounds(&mut b, rounds);
            let difference = a
                .iter()
                .zip(b.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum::<u32>();
            key_total += u64::from(difference);
            key_min = key_min.min(difference);
            key_max = key_max.max(difference);
        }
        println!(
            "  rounds={rounds:>2} plaintext_avg={:.2} min={plaintext_min} max={plaintext_max} key_avg={:.2} min={key_min} max={key_max}",
            plaintext_total as f64 / cases as f64,
            key_total as f64 / cases as f64
        );
    }
    println!("Avalanche statistics are sanity checks, not security bounds.");
}
