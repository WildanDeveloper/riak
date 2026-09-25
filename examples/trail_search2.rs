//! Trail search restricted to the DETERMINISTIC differential of F:
//!
//!   dx = 0x80000000  ->  eta* = 0x02400180  with DP = 1
//!
//! Why deterministic (verified analytically and numerically):
//! x ^ 0x80000000 == x + 0x80000000 (mod 2^32) keeps the add/multiply
//! stages carry-free; 2^31 * M mod 2^32 == 2^31 because M is odd; the
//! xor-rotate stage is linear. Independent of round keys and constants,
//! so it works in every round.
//!
//! Question: does an activation pattern exist where EVERY active round
//! takes dx = 0x80000000? If yes, the 24-round trail has DP = 1 — a
//! free distinguisher. Exact GF(2) feasibility per pattern.
//!
//! Model per bit position b (independent linear systems):
//!   unknowns x_b = bits of the 4 base difference words
//!   each state word bit = coeff·x_b ^ k_b  (k = accumulated eta* mask)
//!   inactive round: delta bit b must be 0
//!   active round:   delta bit b must be 0 for b != 31, 1 for b == 31
//!                   (delta is exactly 0x80000000)
//!
//! Run: cargo run --release --example trail_search2

const ROUNDS: usize = 24;
const DP1_ETA: u32 = 0x0240_0180;

#[derive(Clone, Copy)]
struct Word {
    c: [u8; 4], // GF(2) coefficients over the 4 base words
    k: u32,     // constant mask (accumulated eta* contributions)
}

impl Word {
    fn base(i: usize) -> Self {
        let mut c = [0u8; 4];
        c[i] = 1;
        Word { c, k: 0 }
    }
    fn xor(self, o: Word) -> Word {
        let mut c = [0u8; 4];
        for i in 0..4 {
            c[i] = self.c[i] ^ o.c[i];
        }
        Word { c, k: self.k ^ o.k }
    }
}

/// GF(2) rank of rows packed as u64 (low bits first), `cols` columns.
fn rank(rows: &[u64]) -> usize {
    let mut basis: [u64; 64] = [0; 64];
    for &row in rows {
        let mut x = row;
        while x != 0 {
            let hb = 63 - x.leading_zeros() as usize;
            if basis[hb] == 0 {
                basis[hb] = x;
                break;
            }
            x ^= basis[hb];
        }
    }
    basis.iter().filter(|&&b| b != 0).count()
}

/// Check one activation pattern (bit r set = round r active).
fn check(pattern: u32) -> bool {
    let mut w: [Word; 4] = [Word::base(0), Word::base(1), Word::base(2), Word::base(3)];
    // One row per round: (coeffs, target mask, k mask).
    // Equation for bit b:  coeff·x_b = target[b] ^ k[b]
    let mut rows: Vec<([u8; 4], u32, u32)> = Vec::new();

    for r in 0..ROUNDS {
        let d = w[1].xor(w[2]).xor(w[3]);
        if pattern >> r & 1 == 1 {
            // delta must equal 0x80000000: target mask = bit 31
            rows.push((d.c, 0x8000_0000, d.k));
            let next = w[0].xor(Word { c: [0; 4], k: DP1_ETA });
            w = [w[1], w[2], w[3], next];
        } else {
            // delta must be 0: target mask = 0
            rows.push((d.c, 0, d.k));
            w = [w[1], w[2], w[3], w[0]];
        }
    }

    // Matrix A (rows = rounds, 4 columns) and 32 rhs vectors.
    let a_rows: Vec<u64> = rows
        .iter()
        .map(|(c, _, _)| {
            let mut v = 0u64;
            for (i, &ci) in c.iter().enumerate() {
                v |= (ci as u64) << i;
            }
            v
        })
        .collect();
    let rank_a = rank(&a_rows);

    for b in 0..32u32 {
        let mut aug: Vec<u64> = a_rows.clone();
        for (r, (_, target, k)) in rows.iter().enumerate() {
            let rhs = ((target >> b) & 1) ^ ((k >> b) & 1);
            aug[r] |= (rhs as u64) << 4; // rhs as 5th column
        }
        if rank(&aug) != rank_a {
            return false; // this bit position is unsatisfiable
        }
    }
    true
}

fn main() {
    println!(
        "Exhaustive search for DP=1 trails (every active round takes dx=0x80000000)\n"
    );
    let mut feasible = 0u64;
    let mut min_active = usize::MAX;
    for pattern in 1u32..(1 << ROUNDS) { // pattern 0 = trivial zero trail
        if check(pattern) {
            feasible += 1;
            min_active = min_active.min(pattern.count_ones() as usize);
        }
    }
    println!("feasible patterns: {feasible} / {}", 1u64 << ROUNDS);
    if feasible > 0 {
        println!("minimum active rounds in a DP=1 trail: {min_active}");
        println!("VERDICT: a probability-1 differential distinguisher EXISTS —");
        println!("the cipher is broken as designed and must be changed.");
    } else {
        println!("VERDICT: no DP=1 trail exists — the deterministic differential");
        println!("cannot chain through the 4-branch structure. Good news.");
        println!("Next refinement: allow DP=2^-1 rounds (dx = 2^31 ^ low bits).");
    }
}
