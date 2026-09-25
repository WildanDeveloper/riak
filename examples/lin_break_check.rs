//! Cross-check of the Python finding: deterministic linear relation.
//!
//! Claim: for a in {0x33333333, 0x55555555, 0x99999999} (kernel of the
//! transpose of F's sequential rotation-xor linear layer),
//!     parity(a · P[1]) == parity(a · C[1])
//! for EVERY plaintext and EVERY key, over the full 24 rounds.
//! If true, RIAK is linearly distinguishable from random with 2 blocks.
//!
//! Run: cargo run --release --example lin_break_check

#![allow(deprecated)]

use riak::Riak;

fn parity(x: u32, m: u32) -> u32 {
    (x & m).count_ones() & 1
}

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
    let mut rng = Rng(0xB1EA_1234_5678_9ABC);
    let key: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher = Riak::from_words(key);
    let key2: [u32; 16] = std::array::from_fn(|_| rng.word());
    let cipher2 = Riak::from_words(key2);

    const N: usize = 100_000;
    for a in [0x3333_3333u32, 0x5555_5555, 0x9999_9999] {
        for (name, c) in [("key1", &cipher), ("key2", &cipher2)] {
            let mut bad = 0usize;
            for _ in 0..N {
                let mut p = [rng.word(), rng.word(), rng.word(), rng.word()];
                let expected = parity(p[1], a);
                c.encrypt_block(&mut p);
                if parity(p[1], a) != expected {
                    bad += 1;
                }
            }
            println!(
                "a={a:08x} {name}: violations {bad}/{N} {}",
                if bad == 0 { "<< DETERMINISTIC — BREAK" } else { "" }
            );
            assert_eq!(bad, 0, "v0.1 linear break regression");
        }
    }
}
