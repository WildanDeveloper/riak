//! Impossible-differential and boomerang screen for RIAK v0.3.
//!
//! Two attack families that the project has not yet covered:
//!
//! 1. **Impossible differentials.** A block difference that can never reach
//!    zero output difference. Such a trail is a distinguisher on its own: it
//!    proves the cipher is not a permutation family in the differential sense.
//!    The structural fact that makes this screen meaningful is that the round
//!    function is a bijection, so the DDT zero column is empty. This tool tests
//!    the full 24-round cipher over many structured input differences and
//!    counts how often the output difference is zero. The correct answer is
//!    never; any observation of a dead difference is a finding.
//!
//! 2. **Boomerang.** A boomerang attack needs a high-probability forward
//!    differential and a high-probability backward differential that meet in the
//!    middle. The full cipher's DDT is not computable, so this tool measures the
//!    *empirical* probability of the best differential trails it can evaluate
//!    directly, at the round counts where a boomerang would actually be staged.
//!    Measuring a probability is not bounding it: a low measured probability
//!    does not prove the true probability is low.
//!
//! This is a bounded screen. It does not bound the space of differences and it
//! does not produce a full differential bound.

use std::collections::HashMap;

use riak::v3::RiakV3;

/// Structured input differences to test. Single-word, all-word, and
/// cross-word patterns are included because they are the shapes a differential
/// cryptanalyst tries first.
fn difference_family() -> Vec<[u32; 4]> {
    let mut family = Vec::new();
    // Every single-bit difference in every word.
    for word in 0..4usize {
        for bit in 0..32u32 {
            let mut delta = [0u32; 4];
            delta[word] = 1u32 << bit;
            family.push(delta);
        }
    }
    // Every single-word all-ones difference.
    for word in 0..4usize {
        let mut delta = [0u32; 4];
        delta[word] = 0xFFFF_FFFF;
        family.push(delta);
    }
    // All four words.
    family.push([0xFFFF_FFFF; 4]);
    // Two-word combinations.
    for left in 0..4usize {
        for right in (left + 1)..4usize {
            let mut delta = [0u32; 4];
            delta[left] = 0xFFFF_FFFF;
            delta[right] = 0xFFFF_FFFF;
            family.push(delta);
        }
    }
    // Three-word combinations.
    for skip in 0..4usize {
        let mut delta = [0xFFFF_FFFF; 4];
        delta[skip] = 0;
        family.push(delta);
    }
    family
}

fn next_random(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// A random 16-word key.
fn random_key(state: &mut u64) -> [u32; 16] {
    let mut key = [0u32; 16];
    for word in key.iter_mut() {
        *word = next_random(state) as u32;
    }
    key
}

fn main() {
    println!("RIAK v0.3 impossible-differential and boomerang screen");
    println!("bounded screen: not a proof, and not a differential bound");
    println!();

    let mut state = 0xDEAD_BEEF_CAFE_1234u64;

    // -------------------------------------------------------------------
    // 1. Impossible differentials over the full cipher.
    // -------------------------------------------------------------------
    println!("[1] impossible differentials: can a block difference die?");
    let family = difference_family();
    let trials = 20_000usize;
    let mut total_dead = 0u64;
    let mut total_pairs = 0u64;
    let mut worst_dead_delta: Option<[u32; 4]> = None;

    for delta in &family {
        for _ in 0..trials {
            let mut base = [0u32; 4];
            for word in base.iter_mut() {
                *word = next_random(&mut state) as u32;
            }
            let cipher = RiakV3::from_words(random_key(&mut state));
            let mut right = [
                base[0] ^ delta[0],
                base[1] ^ delta[1],
                base[2] ^ delta[2],
                base[3] ^ delta[3],
            ];
            let mut left = base;
            cipher.encrypt_block(&mut left);
            cipher.encrypt_block(&mut right);
            if left == right {
                total_dead += 1;
                worst_dead_delta.get_or_insert(*delta);
            }
            total_pairs += 1;
        }
    }
    println!("    structured differences tested: {}", family.len());
    println!("    plaintext pairs per difference: {trials}");
    println!("    total pairs:                   {total_pairs}");
    println!("    output differences equal to zero: {total_dead}");
    if total_dead == 0 {
        println!("    RESULT: no impossible differential was observed");
    } else {
        println!("    RESULT: a dead output difference was observed");
        if let Some(delta) = worst_dead_delta {
            println!("    example difference: {delta:08X?}");
        }
    }
    println!();

    // -------------------------------------------------------------------
    // 2. Empirical differential probabilities at reduced round counts.
    // -------------------------------------------------------------------
    // A boomerang is staged at some round count r with a forward trail
    // covering the first r rounds and a backward trail covering the rest. The
    // screening question is how strong a single differential can be at small
    // r. The full DDT is not computable, so this measures the empirical
    // probability of the best fixed output difference for a fixed input
    // difference, over random keys and plaintexts.
    println!("[2] empirical differential probability by round count");
    println!("    for a fixed input difference, the best matching output difference");
    let delta: [u32; 4] = [0x8000_0000, 0, 0, 0];
    let samples = 4096usize;
    println!("    input difference: {delta:08X?}");
    println!("    samples per round count: {samples}");
    println!("    {:>6}  {:>10}  {:>12}", "rounds", "best count", "probability");
    for rounds in [1usize, 2, 4, 6, 8, 12, 16, 20, 24] {
        let mut histogram: HashMap<[u32; 4], u32> = HashMap::new();
        for _ in 0..samples {
            let mut base = [0u32; 4];
            for word in base.iter_mut() {
                *word = next_random(&mut state) as u32;
            }
            let cipher = RiakV3::from_words(random_key(&mut state));
            let mut right = [
                base[0] ^ delta[0],
                base[1] ^ delta[1],
                base[2] ^ delta[2],
                base[3] ^ delta[3],
            ];
            let mut left = base;
            cipher.encrypt_block_rounds(&mut left, rounds);
            cipher.encrypt_block_rounds(&mut right, rounds);
            let mut difference = [0u32; 4];
            for word in 0..4usize {
                difference[word] = left[word] ^ right[word];
            }
            *histogram.entry(difference).or_insert(0) += 1;
        }
        let best = histogram.values().copied().max().unwrap_or(0);
        println!(
            "    {rounds:>6}  {best:>10}  {:>12}",
            format!("{:.6}", best as f64 / samples as f64)
        );
    }
    println!();
    println!("    reference: for a random permutation, the best of many distinct outputs");
    println!("    over thousands of samples is expected near 1, so a rising count with rounds is");
    println!("    the signature of a converging differential. Flat counts mean the output");
    println!("    difference stays spread out as the round count grows.");
    println!();

    println!("what this screen does NOT establish:");
    println!("  - it measures one input difference; a full differential bound needs all of them");
    println!("  - a low measured probability is not a proven low probability");
    println!("  - no boomerang distinguisher is constructed or run end to end");
    println!("  - the full-width differential and linear hull bounds remain open");
}
