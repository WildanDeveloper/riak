//! Full-block empirical differential screen for RIAK v0.3.
//! This is a screening tool, not a trail proof.
//! Run: cargo run --release --example v3_differential [trials]

use riak::v3::RiakV3;
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
        .unwrap_or(1 << 18);
    let mut rng = Rng(0xD1CE_D1FF_1234_5679);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = RiakV3::from_words(key);

    let differences: [(&str, [u32; 4]); 5] = [
        ("one-bit-x0", [1, 0, 0, 0]),
        ("one-bit-x1", [0, 1, 0, 0]),
        ("high-bit-x3", [0, 0, 0, 0x8000_0000]),
        ("full-x0", [0xffff_ffff, 0, 0, 0]),
        ("full-all", [0xffff_ffff; 4]),
    ];

    println!("RIAK v0.3 full differential screen: {trials} pairs/cell");
    for rounds in [1usize, 2, 4, 6, 8, 12, 24] {
        for (name, delta) in differences {
            let mut counts = HashMap::new();
            for _ in 0..trials {
                let first = rng.block();
                let mut second = first;
                for i in 0..4 {
                    second[i] ^= delta[i];
                }
                let mut a = first;
                let mut b = second;
                cipher.encrypt_block_rounds(&mut a, rounds);
                cipher.encrypt_block_rounds(&mut b, rounds);
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
                "  {name:<14} rounds={rounds:>2} top={:08x}{:08x}{:08x}{:08x} hits={hits} dp={:.3e}",
                top[0],
                top[1],
                top[2],
                top[3],
                *hits as f64 / trials as f64
            );
        }
    }
    println!("No result here is a proof of differential security.");
}
