//! Mixed high-DP trail search.
//!
//! Extends trail_search2: active rounds may use any input difference
//! with measured high DP (top bit + up to 2 low bits), each with its
//! measured max-DP output difference eta. Question: what is the
//! highest-DP feasible trail through 24 rounds? Any trail above
//! ~2^-128 is a distinguisher.
//!
//! Exact method: DFS over rounds; at each round branch on
//!   - inactive (delta = 0, DP factor 1), or
//!   - active with candidate delta s (DP factor dp(s), state absorbs
//!     the measured eta(s) as a constant).
//! Constraints "delta_r == s_r" are linear per bit over the 4 base
//! words; consistency is maintained incrementally with a per-bit
//! GF(2) augmented basis. A completed path = feasible trail.
//!
//! Run: cargo run --release --example trail_search3

const ROUNDS: usize = 24;
const TOP: u32 = 0x8000_0000;
const SAMPLES: u32 = 1 << 20; // per-candidate DP measurement
const KEY: u32 = 0xA5A5_5A5A;
const C: u32 = 17;
const NODE_BUDGET: u64 = 2_000_000_000;

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

#[inline(always)]
fn f(x: u32, k: u32, c: u32) -> u32 {
    const MUL: u32 = 0x9E37_79B9;
    let mut t = x ^ k;
    t = t.wrapping_add(c);
    t = t.wrapping_mul(MUL);
    t ^= t.rotate_left(9);
    t ^= t.rotate_left(17);
    t ^= t.rotate_left(23);
    t
}

/// Candidate deltas: top bit alone, or top bit + up to 2 low bits.
fn candidates() -> Vec<u32> {
    let mut v = vec![TOP];
    for i in 0..31u32 {
        v.push(TOP | (1 << i));
    }
    for i in 0..31u32 {
        for j in (i + 1)..31u32 {
            v.push(TOP | (1 << i) | (1 << j));
        }
    }
    v
}

/// Measure (top eta, DP) for a delta by sampling.
fn measure(dx: u32, rng: &mut Rng) -> (u32, f64) {
    // small open-addressing histogram via HashMap is fine at this scale
    let mut counts = std::collections::HashMap::new();
    for _ in 0..SAMPLES {
        let x = rng.word();
        let dy = f(x, KEY, C) ^ f(x ^ dx, KEY, C);
        *counts.entry(dy).or_insert(0u32) += 1;
    }
    let (dy, &hits) = counts.iter().max_by_key(|(_, c)| **c).unwrap();
    (*dy, hits as f64 / SAMPLES as f64)}

#[derive(Clone, Copy)]
struct Word {
    c: [u8; 4],
    k: u32,
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

/// Per-bit augmented GF(2) basis: for each of 32 bits, up to 4 rows of
/// 5 bits (4 coefficients + rhs).
type Bits = Vec<[[u8; 5]; 4]>;

fn new_bits() -> Bits {
    vec![[[0; 5]; 4]; 32]
}

/// Try to add equation coeff·x = rhs for bit b. Returns false on contradiction.
fn add_eq(bits: &mut Bits, b: usize, coeff: &[u8; 4], rhs: u8) -> bool {
    let mut row = [0u8; 5];
    for i in 0..4 {
        row[i] = coeff[i];
    }
    row[4] = rhs;
    for r in 0..4 {
        if row[r] == 1 {
            let pivot = bits[b][r];
            if pivot == [0u8; 5] {
                bits[b][r] = row;
                return true;
            }
            for i in 0..5 {
                row[i] ^= pivot[i];
            }
        }
    }
    // row now has all-zero coefficients
    row[4] == 0
}

/// DFS state
struct Search {
    bits: Bits,
    best_log2dp: f64,
    best_trail: Vec<(usize, u32, u32, f64)>, // (round, s, eta, dp)
    trail: Vec<(usize, u32, u32, f64)>,
    nodes: u64,
    budget: u64,
    aborted: bool,
    cands: Vec<(u32, u32, f64)>, // (s, eta, dp)
}

impl Search {
    fn dfs(&mut self, w: &[Word; 4], r: usize, log2dp: f64) {
        if self.aborted {
            return;
        }
        self.nodes += 1;
        if self.nodes > self.budget {
            self.aborted = true;
            return;
        }
        if r == ROUNDS {
            // Only non-trivial trails (at least one active round) count.
            // The all-inactive path with zero base words is the zero
            // difference, not a distinguisher.
            if !self.trail.is_empty() && log2dp > self.best_log2dp {
                self.best_log2dp = log2dp;
                self.best_trail = self.trail.clone();
            }
            return;
        }
        let d = w[1].xor(w[2]).xor(w[3]);

        // Branch 1..: active with candidate s (high DP first — find
        // breaking trails fast).
        let cands = self.cands.clone();
        for &(s, eta, dp) in &cands {
            let l2 = dp.log2();
            // delta must equal s exactly
            let mut bits2 = self.bits.clone();
            let mut ok = true;
            for b in 0..32 {
                let req = (s >> b & 1) as u8;
                let rhs = req ^ ((d.k >> b) & 1) as u8;
                if !add_eq(&mut bits2, b, &d.c, rhs) {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }
            let wnext = w[0].xor(Word { c: [0; 4], k: eta });
            let w2 = [w[1], w[2], w[3], wnext];
            self.trail.push((r, s, eta, dp));
            let saved = std::mem::replace(&mut self.bits, bits2);
            self.dfs(&w2, r + 1, log2dp + l2);
            self.bits = saved;
            self.trail.pop();
        }

        // Branch last: inactive (delta = 0).
        let mut bits2 = self.bits.clone();
        let mut ok = true;
        for b in 0..32 {
            let rhs = ((d.k >> b) & 1) as u8;
            if !add_eq(&mut bits2, b, &d.c, rhs) {
                ok = false;
                break;
            }
        }
        if ok {
            let w2 = [w[1], w[2], w[3], w[0]];
            let saved = std::mem::replace(&mut self.bits, bits2);
            self.dfs(&w2, r + 1, log2dp);
            self.bits = saved;
        }
    }
}

fn main() {
    let mut rng = Rng(0x5EED_5EED_5EED_0001);
    println!("Phase 1: measuring high-DP candidates ({} deltas x 2^{} samples)...",
        1 + 31 + 465, SAMPLES.trailing_zeros());
    let mut cands: Vec<(u32, u32, f64)> = Vec::new(); // (s, eta, dp)
    for &s in &candidates() {
        let (eta, dp) = measure(s, &mut rng);
        cands.push((s, eta, dp));
    }
    cands.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    println!("best 5 candidates:");
    for (s, eta, dp) in cands.iter().take(5) {
        println!("  s={s:08x} eta={eta:08x} dp={dp:.4} (2^{:.1})", dp.log2());
    }

    println!("\nPhase 2: DFS over activation + candidate choices (budget {NODE_BUDGET} nodes)...");
    let w0 = [Word::base(0), Word::base(1), Word::base(2), Word::base(3)];
    let mut search = Search {
        bits: new_bits(),
        best_log2dp: -999.0,
        best_trail: Vec::new(),
        trail: Vec::new(),
        nodes: 0,
        budget: NODE_BUDGET,
        aborted: false,
        cands,
    };
    search.dfs(&w0, 0, 0.0);

    println!("\nnodes explored: {}", search.nodes);
    if search.aborted {
        println!("NOTE: node budget exhausted — result is a LOWER bound on the");
        println!("best trail DP, not the exact maximum.");
    }
    if search.best_trail.is_empty() {
        println!("best trail: none found within budget (only trivial zero trail exists)");
        println!("\nVERDICT: inconclusive within budget — needs stronger tooling");
        println!("(MILP / meet-in-the-middle). No distinguisher FOUND so far.");
    } else {
        println!("best trail DP: 2^{:.1}", search.best_log2dp);
        println!("best trail (round, delta, eta, dp):");
        for (r, s, eta, dp) in &search.best_trail {
            println!("  round {r:>2}: s={s:08x} eta={eta:08x} dp={dp:.4}");
        }
        if search.best_log2dp > -128.0 {
            println!("\nVERDICT: a trail above 2^-128 EXISTS — distinguisher found,");
            println!("the design must be revised.");
        } else {
            println!("\nVERDICT: best feasible trail is below 2^-128 — no distinguisher");
            println!("from this trail family.");
        }
    }
}
