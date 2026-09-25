//! Mixed high-DP trail search — fast variant of trail_search3.
//!
//! Same traversal order and semantics as trail_search3/trail_search3p.
//! Differences (performance only):
//!   - constraint basis updated IN PLACE with an undo log instead of
//!     cloning the full Bits per candidate,
//!   - cands iterated by index (no per-node Vec clone),
//!   - log2(dp) precomputed,
//!   - node budget and progress interval from CLI args.
//!
//! Validation protocol: run trail_search3p and this with the same small
//! budget; node counts, hit sequence and best trail must be identical.
//!
//! Run: cargo run --release --example trail_search3f [budget] [report_every]

const ROUNDS: usize = 24;
const TOP: u32 = 0x8000_0000;
const SAMPLES: u32 = 1 << 20; // per-candidate DP measurement
const KEY: u32 = 0xA5A5_5A5A;
const C: u32 = 17;

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
    let mut counts = std::collections::HashMap::new();
    for _ in 0..SAMPLES {
        let x = rng.word();
        let dy = f(x, KEY, C) ^ f(x ^ dx, KEY, C);
        *counts.entry(dy).or_insert(0u32) += 1;
    }
    let (dy, &hits) = counts.iter().max_by_key(|(_, c)| **c).unwrap();
    (*dy, hits as f64 / SAMPLES as f64)
}

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

/// Try to add equation coeff·x = rhs for bit b, mutating `bits` IN PLACE.
/// Every pivot slot written is recorded in `undo` as (b, r); callers must
/// undo (zero those slots) on failure or after exploring the branch.
/// Pivots are only ever written when previously [0;5], so undoing is
/// always "restore to zero". Returns false on contradiction.
fn add_eq_inplace(
    bits: &mut Bits,
    b: usize,
    coeff: &[u8; 4],
    rhs: u8,
    undo: &mut Vec<(usize, usize)>,
) -> bool {
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
                undo.push((b, r));
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
    cands: Vec<(u32, u32, f64, f64)>, // (s, eta, dp, log2dp)
    start: std::time::Instant,
    report_every: u64,
    last_report: u64,
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
        if self.nodes >= self.last_report {
            let el = self.start.elapsed().as_secs_f64();
            eprintln!(
                "[progress] nodes={} elapsed={:.0}s rate={:.0}/s best={}",
                self.nodes,
                el,
                self.nodes as f64 / el,
                if self.best_trail.is_empty() {
                    "none".to_string()
                } else {
                    format!("2^{:.1}", self.best_log2dp)
                }
            );
            self.last_report = self.nodes + self.report_every;
        }
        if r == ROUNDS {
            // Only non-trivial trails (at least one active round) count.
            // The all-inactive path with zero base words is the zero
            // difference, not a distinguisher.
            if !self.trail.is_empty() && log2dp > self.best_log2dp {
                self.best_log2dp = log2dp;
                self.best_trail = self.trail.clone();
                eprintln!(
                    "[hit] nodes={} best=2^{:.1} trail_len={}",
                    self.nodes,
                    log2dp,
                    self.trail.len()
                );
            }
            return;
        }
        let d = w[1].xor(w[2]).xor(w[3]);

        // Branch 1..: active with candidate s (high DP first — find
        // breaking trails fast). In-place constraint update with undo.
        let mut undo: Vec<(usize, usize)> = Vec::new();
        for ci in 0..self.cands.len() {
            let (s, eta, _dp, l2) = self.cands[ci];
            // delta must equal s exactly
            undo.clear();
            let mut ok = true;
            for b in 0..32 {
                let req = (s >> b & 1) as u8;
                let rhs = req ^ ((d.k >> b) & 1) as u8;
                if !add_eq_inplace(&mut self.bits, b, &d.c, rhs, &mut undo) {
                    ok = false;
                    break;
                }
            }
            if ok {
                let wnext = w[0].xor(Word { c: [0; 4], k: eta });
                let w2 = [w[1], w[2], w[3], wnext];
                self.trail.push((r, s, eta, self.cands[ci].2));
                self.dfs(&w2, r + 1, log2dp + l2);
                self.trail.pop();
            }
            // undo this candidate's constraint updates
            for &(b, rr) in &undo {
                self.bits[b][rr] = [0u8; 5];
            }
        }

        // Branch last: inactive (delta = 0).
        undo.clear();
        let mut ok = true;
        for b in 0..32 {
            let rhs = ((d.k >> b) & 1) as u8;
            if !add_eq_inplace(&mut self.bits, b, &d.c, rhs, &mut undo) {
                ok = false;
                break;
            }
        }
        if ok {
            let w2 = [w[1], w[2], w[3], w[0]];
            self.dfs(&w2, r + 1, log2dp);
        }
        for &(b, rr) in &undo {
            self.bits[b][rr] = [0u8; 5];
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let budget: u64 = args
        .get(1)
        .map(|s| s.parse().expect("budget must be u64"))
        .unwrap_or(2_000_000_000);
    let report_every: u64 = args
        .get(2)
        .map(|s| s.parse().expect("report_every must be u64"))
        .unwrap_or(1 << 27);

    let mut rng = Rng(0x5EED_5EED_5EED_0001);
    println!(
        "Phase 1: measuring high-DP candidates ({} deltas x 2^{} samples)...",
        1 + 31 + 465,
        SAMPLES.trailing_zeros()
    );
    let mut cands: Vec<(u32, u32, f64, f64)> = Vec::new(); // (s, eta, dp, log2dp)
    for &s in &candidates() {
        let (eta, dp) = measure(s, &mut rng);
        cands.push((s, eta, dp, dp.log2()));
    }
    cands.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    println!("best 5 candidates:");
    for (s, eta, dp, _) in cands.iter().take(5) {
        println!("  s={s:08x} eta={eta:08x} dp={dp:.4} (2^{:.1})", dp.log2());
    }

    println!("\nPhase 2: DFS over activation + candidate choices (budget {budget} nodes)...");
    let w0 = [Word::base(0), Word::base(1), Word::base(2), Word::base(3)];
    let mut search = Search {
        bits: new_bits(),
        best_log2dp: -999.0,
        best_trail: Vec::new(),
        trail: Vec::new(),
        nodes: 0,
        budget,
        aborted: false,
        cands,
        start: std::time::Instant::now(),
        report_every,
        last_report: report_every,
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
