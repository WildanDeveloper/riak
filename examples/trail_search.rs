//! Exhaustive differential trail search over the activation patterns of F.
//!
//! Question being answered (krip.md "Temuan #1"): can a differential
//! trail through 24 rounds survive with few active F calls, so that the
//! per-F DP of ~2^-11 multiplies into something above 2^-128?
//!
//! Method — exact, not sampled:
//! 1. Enumerate all 2^24 activation patterns (bit r = 1 if F is active
//!    in round r).
//! 2. For each pattern, propagate differences SYMBOLICALLY. Every
//!    state word is a GF(2) linear combination of free symbols:
//!    4 base difference words (attacker's choice) + one output
//!    difference per active F. An inactive round (F input difference
//!    forced to zero) contributes a linear constraint on the symbols.
//! 3. A pattern is feasible iff there is a symbol assignment with:
//!    - every inactive-round constraint satisfied,
//!    - every active-round F input difference NONZERO (otherwise that
//!      round is really inactive and its true pattern is enumerated
//!      separately),
//!    - overall input difference nonzero.
//!    All conditions reduce to rowspace membership tests in a 28-dim
//!    GF(2) space.
//! 4. Upper-bound the trail DP of every feasible pattern by
//!    2^(-11 * active_count), using the measured max DP of F.
//!
//! Soundness notes (deliberate relaxations, all in the attacker's
//! favor): every active F is assumed to achieve its max DP 2^-11 for
//! any required input difference, and every nonzero output difference
//! is assumed reachable. The result is therefore an UPPER bound on
//! what any differential characteristic can achieve.
//!
//! Run: cargo run --release --example trail_search

const BASE: usize = 4; // base difference words (attacker's choice)
const ROUNDS: usize = 24;
const SYMS: usize = BASE + ROUNDS; // symbol space dimension

/// Max measured DP of F (see ddt_focus): 2^-11.0.
const LOG2_MAX_DP_F: i32 = -11;

/// GF(2) rank of a multiset of vectors in SYMS-dimensional space.
fn rank(vectors: &[u32]) -> usize {
    let mut basis = [0u32; SYMS];
    for &v in vectors {
        let mut x = v;
        while x != 0 {
            let b = 31 - x.leading_zeros() as usize;
            if basis[b] == 0 {
                basis[b] = x;
                break;
            }
            x ^= basis[b];
        }
    }
    basis.iter().filter(|&&b| b != 0).count()
}

/// Is `v` in the rowspace of `rows`? Equivalent to rank(rows) == rank(rows ∪ {v}).
fn in_rowspace(rows: &[u32], v: u32) -> bool {
    let mut all = rows.to_vec();
    all.push(v);
    rank(&all) == rank(rows)
}

/// Feasibility check for one activation pattern over `rounds` rounds.
/// Returns Some(active_count) if feasible, None if infeasible.
fn check(pattern: u32, rounds: usize) -> Option<usize> {
    // Symbolic state: sliding window of 4 words, each a SYMS-bit mask
    // over the symbol space. Words are GF(2) combinations of symbols.
    let mut w: [u32; 4] = [1 << 0, 1 << 1, 1 << 2, 1 << 3];
    let mut deltas = [0u32; ROUNDS]; // F input-difference mask per round
    let mut constraints: Vec<u32> = Vec::new();
    let mut active_count = 0usize;

    for r in 0..rounds {
        let d = w[1] ^ w[2] ^ w[3];
        deltas[r] = d;
        if pattern >> r & 1 == 1 {
            // F active: fresh output-difference symbol enters the state.
            let next = w[0] ^ (1 << (BASE + r));
            w = [w[1], w[2], w[3], next];
            active_count += 1;
        } else {
            // F inactive: input difference must be zero (constraint);
            // output difference is zero, word passes through unchanged.
            constraints.push(d);
            w = [w[1], w[2], w[3], w[0]];
        }
    }

    // Condition A: every active round needs a symbol assignment with
    // nonzero F input difference. Its delta functional vanishes on the
    // constraint nullspace iff the mask lies in rowspace(constraints).
    // Zero mask = round really inactive = enumerated under its own
    // pattern, so rejecting here is sound.
    for r in 0..rounds {
        if pattern >> r & 1 == 1 && (deltas[r] == 0 || in_rowspace(&constraints, deltas[r])) {
            return None;
        }
    }

    // Condition B: overall input difference must be able to be nonzero:
    // some base unit vector must NOT be in rowspace(constraints)
    // (otherwise every solution has all base words zero).
    if (0..BASE).all(|i| in_rowspace(&constraints, 1 << i)) {
        return None;
    }

    Some(active_count)
}

fn main() {
    println!("Exhaustive activation-pattern search over {ROUNDS} rounds");
    println!("symbol space: {SYMS} dims (4 base words + 1 per active F)\n");

    for rounds in [8usize, 12, 16, 20, 24] {
        let mut min_active = usize::MAX;
        let mut feasible = 0u64;
        let patterns = 1u32 << rounds;
        for pattern in 0..patterns {
            if let Some(a) = check(pattern, rounds) {
                feasible += 1;
                min_active = min_active.min(a);
            }
        }
        let bound_exp = LOG2_MAX_DP_F * min_active as i32;
        println!(
            "rounds={rounds:>2}  feasible={feasible:>10}  min_active={min_active:>2}  loose DP bound=2^{bound_exp}"
        );
    }

    println!("\nNote: the flat 2^-11 max-DP assumption is crude; see dp_scan");
    println!("for per-difference refinement and krip.md for the verdict.");
}
