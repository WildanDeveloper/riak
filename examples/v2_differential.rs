//! Full-block empirical differential screen for RIAK v0.2.
//! This is a screening tool, not a trail proof.
//! Run: cargo run --release --example v2_differential [trials]

use riak::v2::RiakV2;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trials: u32 = args
        .get(1)
        .map(|value| value.parse().expect("trials must be an integer"))
        .unwrap_or(1 << 20);
    let mut rng = Rng(0xD1CE_D1FF_1234_5678);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = RiakV2::from_words(key);

    let differences: [(&str, [u32; 4]); 4] = [
        ("one-bit-x0", [1, 0, 0, 0]),
        ("high-bit-x3", [0, 0, 0, 0x8000_0000]),
        ("full-x0", [0xffff_ffff, 0, 0, 0]),
        ("full-all", [0xffff_ffff; 4]),
    ];

    println!("RIAK v0.2 full differential screen: {trials} pairs/cell");
    for rounds in [4usize, 6, 8, 12, 24] {
        for (name, delta) in differences {
            let mut counts = HashMap::new();
            for _ in 0..trials {
                let mut first = rng.block();
                let mut second = first;
                for i in 0..4 {
                    second[i] ^= delta[i];
                }
                cipher.encrypt_block_rounds(&mut first, rounds);
                cipher.encrypt_block_rounds(&mut second, rounds);
                let output_delta = [
                    first[0] ^ second[0],
                    first[1] ^ second[1],
                    first[2] ^ second[2],
                    first[3] ^ second[3],
                ];
                *counts.entry(output_delta).or_insert(0u32) += 1;
            }
            let (top, hits) = counts.iter().max_by_key(|(_, count)| **count).unwrap();
            println!(
                "  {name:<14} rounds={rounds:>2} top={:08x}{:08x}{:08x}{:08x} hits={hits}",
                top[0], top[1], top[2], top[3]
            );
        }
    }
    println!("No result here is a proof of differential security.");
}
