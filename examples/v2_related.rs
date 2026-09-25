//! Initial related-key smoke probe for RIAK v0.2.
//! Run: cargo run --release --example v2_related [cases]
//!
//! This looks for catastrophic related-key failures; it is not a substitute
//! for a serious related-key cryptanalysis.

use riak::v2::RiakV2;

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
        .unwrap_or(4096);
    let mut rng = Rng(0xA11C_E5E1_1234_5678);
    let mut total = 0u64;
    let mut minimum = 128u32;
    let mut maximum = 0u32;
    let mut zero_output_cases = 0usize;

    for _ in 0..cases {
        let key: [u32; 16] = std::array::from_fn(|_| rng.word());
        let mut changed_key = key;
        let word = (rng.word() as usize) % 16;
        let bit = rng.word() % 32;
        changed_key[word] ^= 1u32 << bit;

        let first = RiakV2::from_words(key);
        let second = RiakV2::from_words(changed_key);
        for _ in 0..4 {
            let plaintext: [u32; 4] = std::array::from_fn(|_| rng.word());
            let mut a = plaintext;
            let mut b = plaintext;
            first.encrypt_block(&mut a);
            second.encrypt_block(&mut b);
            let difference = a
                .iter()
                .zip(b.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum::<u32>();
            total += u64::from(difference);
            minimum = minimum.min(difference);
            maximum = maximum.max(difference);
            zero_output_cases += (difference == 0) as usize;
        }
    }

    println!("RIAK v0.2 related-key smoke probe");
    println!("  cases={cases} blocks_per_case=4");
    println!("  average_output_hamming={:.3}", total as f64 / (cases * 4) as f64);
    println!("  min_output_hamming={minimum} max_output_hamming={maximum}");
    println!("  zero_difference_blocks={zero_output_cases}");
    println!("  This is only a catastrophic-failure screen, not a security bound.");
}
