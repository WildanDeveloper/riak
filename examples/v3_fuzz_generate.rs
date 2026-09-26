//! Emit deterministic RIAK v0.3 wrapper test vectors for independent checking.
//!
//! The point of this tool is to produce a large body of cases that
//! `simulator/fuzz_diff_v3.py` re-derives with the independent Python
//! reference. A divergence between the two implementations is a real defect in
//! at least one of them, and the two share no code, so agreement across
//! millions of cases is meaningful evidence that both are correct.
//!
//! Case generation is fully determined by a seed so a failing case can be
//! reproduced exactly.
//!
//! Usage:
//!   cargo run --release --example v3_fuzz_generate -- <cases> <seed> <out>

use std::io::{BufWriter, Write};

use riak::v3::RiakV3Cipher;

/// xorshift64*, so the case stream is reproducible across machines.
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

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { (self.next() % bound as u64) as usize }
    }
}

/// The shape of a generated case. Message and aad lengths are drawn from a
/// fixed ladder that covers every partial-block case plus multi-block and
/// empty cases, rather than from a uniform random length. Uniform random
/// lengths would almost never hit 0 or 1 mod 16.
const LENGTH_LADDER: [usize; 10] = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: v3_fuzz_generate <cases> <seed> <output>");
        std::process::exit(2);
    }
    let cases: u64 = args[0].parse().expect("cases must be an integer");
    let seed: u64 = args[1].parse().expect("seed must be an integer");
    let path = &args[2];

    let file = std::fs::File::create(path).expect("cannot create output file");
    let mut out = BufWriter::new(file);

    let mut rng = Rng(seed);
    let mut written = 0u64;

    while written < cases {
        let mut key = [0u8; 64];
        for byte in key.iter_mut() {
            *byte = rng.byte();
        }
        let cipher = RiakV3Cipher::new(&key);

        // Emit a small batch of messages under the same key so that key
        // schedule reuse across many messages is exercised too.
        let batch = 1 + rng.below(4);
        for _ in 0..batch {
            if written >= cases {
                break;
            }
            let mut nonce = [0u8; 12];
            for byte in nonce.iter_mut() {
                *byte = rng.byte();
            }
            let message_len = LENGTH_LADDER[rng.below(LENGTH_LADDER.len())]
                + 16 * rng.below(6);
            let aad_len = LENGTH_LADDER[rng.below(LENGTH_LADDER.len())];

            let mut plaintext = vec![0u8; message_len];
            for byte in plaintext.iter_mut() {
                *byte = rng.byte();
            }
            let mut aad = vec![0u8; aad_len];
            for byte in aad.iter_mut() {
                *byte = rng.byte();
            }

            let sealed = cipher
                .seal(&nonce, &aad, &plaintext)
                .expect("seal must succeed for generated sizes");

            // Record: key, nonce, aad, plaintext, sealed. The plaintext is
            // included so the checker can confirm round-trip decryption as
            // well as agreement on the ciphertext and tag.
            write!(out, "K ").unwrap();
            for byte in key.iter() {
                write!(out, "{byte:02x}").unwrap();
            }
            write!(out, " N ").unwrap();
            for byte in nonce.iter() {
                write!(out, "{byte:02x}").unwrap();
            }
            write!(out, " A ").unwrap();
            for byte in aad.iter() {
                write!(out, "{byte:02x}").unwrap();
            }
            write!(out, " P ").unwrap();
            for byte in plaintext.iter() {
                write!(out, "{byte:02x}").unwrap();
            }
            write!(out, " C ").unwrap();
            for byte in sealed.iter() {
                write!(out, "{byte:02x}").unwrap();
            }
            writeln!(out).unwrap();

            written += 1;
        }
    }

    out.flush().expect("cannot flush output");
    println!("wrote {written} case(s) with seed {seed} to {path}");
}
