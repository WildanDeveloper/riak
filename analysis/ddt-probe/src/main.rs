//! Independent reduced-width differential/linear probe for the RIAK v0.3
//! round bijection.
//!
//! This is a **research tool**. It is not part of the `riak` library and it is
//! not a proof of security. It does three things:
//!
//! 1. Re-derives the round function from the documented specification and
//!    cross-checks that copy against the shipped `riak::v2::round_function`.
//! 2. Computes the **exact** difference distribution table (DDT) and linear
//!    approximation table (LAT) of the keyless round bijection truncated to a
//!    reduced word width `w < 32`.
//! 3. Computes the **exact** minimum number of active F evaluations in any
//!    24-round differential trail of the v0.3 four-branch outer network, using
//!    a dynamic program over all 16 difference-activity patterns.
//!
//! Why reduced width carries information: every step of the round function
//! (XOR, modular addition, odd multiplication, shift, rotate) is compatible
//! with projection onto the low `w` bits, so the low `w` bits of the 32-bit
//! output depend only on the low `w` bits of the input. The truncated
//! output-difference distribution is therefore the marginalisation of the
//! full-width distribution, so a large truncated probability is a rigorous red
//! flag. A small truncated probability proves nothing about the full width.
//! Absence of signal must never be reported as evidence of security.
//!
//! Full-width tables are out of reach on any machine: one DDT row already
//! needs `2^32` counters and the table has `2^64` entries.

use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Specification-derived constants and round function (independent copy).
// ---------------------------------------------------------------------------

const MUL_A: u32 = 0x9E37_79B9;
const MUL_B: u32 = 0x85EB_CA6B;
const MUL_C: u32 = 0xC2B2_AE35;
const ADD_A: u32 = 0x7F4A_7C15;
const ADD_B: u32 = 0x1B87_3593;

const PRIMES: [u32; 24] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
];

const SLOT: [u32; 4] = [0x0000_0000, 0x1357_9BDF, 0x2468_ACE0, 0xFEDC_BA98];

#[inline(always)]
fn mix_a(t: u32) -> u32 {
    let mut t = t;
    t ^= t >> 7;
    t = t.rotate_left(11);
    t ^= t << 9;
    t
}

#[inline(always)]
fn mix_b(t: u32) -> u32 {
    let mut t = t;
    t ^= t >> 5;
    t = t.rotate_left(7);
    t ^= t << 13;
    t
}

#[inline(always)]
fn mix_c(t: u32) -> u32 {
    let mut t = t;
    t ^= t >> 17;
    t = t.rotate_left(19);
    t ^= t << 15;
    t
}

/// Independent copy of the documented 32-bit round function.
#[inline(always)]
fn round_function(x: u32, k: u32, c: u32) -> u32 {
    let mut t = x ^ k;
    t = t.wrapping_add(c);
    t = t.wrapping_mul(MUL_A);
    t = mix_a(t);
    t = t.wrapping_add(ADD_A);
    t = t.wrapping_mul(MUL_B);
    t = mix_b(t);
    t = t.wrapping_add(ADD_B);
    t = t.wrapping_mul(MUL_C);
    mix_c(t)
}

// ---------------------------------------------------------------------------
// Reduced-width arithmetic.
// ---------------------------------------------------------------------------

#[inline(always)]
fn mask_w(width: u32) -> u32 {
    (1u32 << width) - 1
}

#[inline(always)]
fn rotl_w(value: u32, amount: u32, width: u32) -> u32 {
    let amount = amount % width;
    if amount == 0 {
        value & mask_w(width)
    } else {
        ((value << amount) | (value >> (width - amount))) & mask_w(width)
    }
}

/// Round function truncated to `width` bits.
#[inline(always)]
fn round_w(x: u32, k: u32, c: u32, width: u32) -> u32 {
    let m = mask_w(width);
    let mut t = (x ^ k) & m;
    t = t.wrapping_add(c) & m;
    t = t.wrapping_mul(MUL_A) & m;
    t ^= t >> 7;
    t = rotl_w(t, 11, width);
    t = (t ^ (t << 9)) & m;
    t = t.wrapping_add(ADD_A) & m;
    t = t.wrapping_mul(MUL_B) & m;
    t ^= t >> 5;
    t = rotl_w(t, 7, width);
    t = (t ^ (t << 13)) & m;
    t = t.wrapping_add(ADD_B) & m;
    t = t.wrapping_mul(MUL_C) & m;
    t ^= t >> 17;
    t = rotl_w(t, 19, width);
    (t ^ (t << 15)) & m
}

// ---------------------------------------------------------------------------
// Specification-derived v0.3 key schedule and outer network.
// ---------------------------------------------------------------------------

const EXTRACTION_SEED: u32 = 0x9E37_79B9;
const EXTRACTION_TAG: u32 = 0x1357_9BDF;
const DOMAIN_DEFAULT: u32 = 0;

fn key_schedule_v3(mut key: [u32; 16], domain: u32) -> [u32; 24] {
    let mut state = key;
    let mut round_keys = [0u32; 24];
    for round in 0..24usize {
        for index in 0..16usize {
            let a = state[(index + 3) & 15];
            let b = state[(index + 7) & 15].rotate_left(11);
            let c = state[(index + 13) & 15].rotate_left(5);
            let mut mixed = a ^ b ^ c;
            let step_constant = (index as u32).wrapping_mul(0x0100_0193);
            let constant = PRIMES[round] ^ SLOT[index & 3] ^ step_constant;
            mixed = round_function(mixed, domain, constant);
            state[index] ^= mixed;
        }
        round_keys[round] = extract_round_key(&state, domain, round);
    }
    key = [0; 16];
    let _ = key;
    round_keys
}

fn extract_round_key(state: &[u32; 16], domain: u32, round: usize) -> u32 {
    let mut accumulator = domain ^ PRIMES[round].wrapping_mul(EXTRACTION_SEED);
    for index in 0..16usize {
        let step = (index as u32).wrapping_mul(0x0100_0193);
        let constant = PRIMES[round] ^ SLOT[index & 3] ^ step ^ EXTRACTION_TAG;
        accumulator = round_function(accumulator ^ state[index], domain ^ step, constant);
    }
    accumulator
}

fn outer_round(block: &mut [u32; 4], key: u32, round: usize) {
    let x0 = block[0];
    let x1 = block[1];
    let x2 = block[2];
    let x3 = block[3];
    let y0 = x0 ^ round_function(x1 ^ x2 ^ x3, key, PRIMES[round] ^ SLOT[0]);
    let y1 = x1 ^ round_function(y0 ^ x2 ^ x3, key, PRIMES[round] ^ SLOT[1]);
    let y2 = x2 ^ round_function(y1 ^ y0 ^ x3, key, PRIMES[round] ^ SLOT[2]);
    let y3 = x3 ^ round_function(y2 ^ y1 ^ y0, key, PRIMES[round] ^ SLOT[3]);
    *block = [y0, y1, y2, y3];
}

fn outer_round_w(block: &mut [u32; 4], key: u32, round: usize, width: u32) {
    let m = mask_w(width);
    let x0 = block[0];
    let x1 = block[1];
    let x2 = block[2];
    let x3 = block[3];
    let y0 = x0 ^ round_w(x1 ^ x2 ^ x3, key, PRIMES[round] ^ SLOT[0], width);
    let y1 = x1 ^ round_w(y0 ^ x2 ^ x3, key, PRIMES[round] ^ SLOT[1], width);
    let y2 = x2 ^ round_w(y1 ^ y0 ^ x3, key, PRIMES[round] ^ SLOT[2], width);
    let y3 = x3 ^ round_w(y2 ^ y1 ^ y0, key, PRIMES[round] ^ SLOT[3], width);
    *block = [y0 & m, y1 & m, y2 & m, y3 & m];
}

fn encrypt_block(round_keys: &[u32; 24], block: &mut [u32; 4]) {
    for round in 0..24usize {
        outer_round(block, round_keys[round], round);
    }
}

fn encrypt_block_w(round_keys: &[u32; 24], block: &mut [u32; 4], width: u32) {
    for round in 0..24usize {
        outer_round_w(block, round_keys[round], round, width);
    }
    let m = mask_w(width);
    for word in block.iter_mut() {
        *word &= m;
    }
}

/// Cross-check the whole specification-derived v0.3 block cipher, including the
/// key schedule and the outer network, against the shipped implementation.
fn cross_check_block(iterations: u64) -> bool {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..iterations {
        let mut key = [0u32; 16];
        for word in key.iter_mut() {
            *word = next() as u32;
        }
        let mut block = [0u32; 4];
        for word in block.iter_mut() {
            *word = next() as u32;
        }
        let reference = {
            let mut copy = block;
            let cipher = riak::v3::RiakV3::from_words(key);
            cipher.encrypt_block(&mut copy);
            copy
        };
        let mut mine = block;
        let round_keys = key_schedule_v3(key, DOMAIN_DEFAULT);
        encrypt_block(&round_keys, &mut mine);
        if mine != reference {
            eprintln!("  mismatch for key {key:08X?} block {block:08X?}");
            eprintln!("  library {reference:08X?}");
            eprintln!("  probe   {mine:08X?}");
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Exact DDT.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct DdtSummary {
    /// Largest output-difference count over all `dx != 0, dy != 0`.
    max_offdiagonal_count: u32,
    arg_dx: u32,
    arg_dy: u32,
    /// Largest count in the zero column, i.e. the largest
    /// `P[F(x) ^ F(x ^ dx) == 0 | dx != 0]`. This is the "absorption"
    /// probability that decides whether an outer branch can stay inactive.
    max_zero_count: u32,
    zero_arg_dx: u32,
    /// Mean zero-column count over all `dx != 0`; a random permutation of this
    /// size has mean 1.
    zero_mean_x1024: u64,
    /// Number of `dx != 0` whose zero-column count exceeds 1.
    zero_above_one: u64,
    /// Number of `dx != 0` that map some `dy` with probability 1.
    deterministic_rows: u64,
    top: [(u32, u32, u32); 4],
    top_zero: [(u32, u32); 4],
}

fn ddt(map: &(dyn Fn(u32) -> u32 + Sync), width: u32, threads: usize) -> DdtSummary {
    let size = 1usize << width;
    let full = size as u32;
    let ranges = split_ranges(size, threads);
    // (max_off, arg_dx, arg_dy, max_zero, zero_dx, zero_sum, zero_above_one,
    //  deterministic, top, top_zero)
    type Partial = (
        u32,
        u32,
        u32,
        u32,
        u32,
        u64,
        u64,
        u64,
        Vec<(u32, u32, u32)>,
        Vec<(u32, u32)>,
    );
    let partials: Vec<Partial> = std::thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .into_iter()
            .map(|(lo, hi)| {
                let map = &*map;
                scope.spawn(move || {
                    let mut counts = vec![0u32; size];
                    let mut best: (u32, u32, u32) = (0, 0, 0);
                    let mut best_zero: (u32, u32) = (0, 0);
                    let mut zero_sum = 0u64;
                    let mut zero_above_one = 0u64;
                    let mut deterministic = 0u64;
                    let mut top: Vec<(u32, u32, u32)> = Vec::new();
                    let mut top_zero: Vec<(u32, u32)> = Vec::new();
                    for dx in lo..hi {
                        for slot in counts.iter_mut() {
                            *slot = 0;
                        }
                        let dx32 = dx as u32;
                        let mut row_max = 0u32;
                        let mut row_arg = 0u32;
                        for x in 0..size {
                            let dy = map(x as u32) ^ map((x as u32) ^ dx32);
                            let slot = &mut counts[dy as usize];
                            *slot += 1;
                            // The zero column is tracked separately and is
                            // excluded from the differential maximum.
                            if *slot > row_max && dy != 0 {
                                row_max = *slot;
                                row_arg = dy;
                            }
                        }
                        if dx32 != 0 {
                            let zero = counts[0];
                            zero_sum += zero as u64;
                            if zero > 1 {
                                zero_above_one += 1;
                            }
                            if zero > best_zero.0 {
                                best_zero = (zero, dx32);
                            }
                            top_zero.push((zero, dx32));
                            if row_max == full {
                                deterministic += 1;
                            }
                            if row_max > best.0 {
                                best = (row_max, dx32, row_arg);
                            }
                            top.push((row_max, dx32, row_arg));
                        }
                    }
                    top.sort_unstable_by(|a, b| b.cmp(a));
                    top.truncate(4);
                    top_zero.sort_unstable_by(|a, b| b.cmp(a));
                    top_zero.truncate(4);
                    (
                        best.0,
                        best.1,
                        best.2,
                        best_zero.0,
                        best_zero.1,
                        zero_sum,
                        zero_above_one,
                        deterministic,
                        top,
                        top_zero,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("ddt worker panicked"))
            .collect()
    });

    let mut best = (0u32, 0u32, 0u32);
    let mut best_zero = (0u32, 0u32);
    let mut zero_sum = 0u64;
    let mut zero_above_one = 0u64;
    let mut deterministic = 0u64;
    let mut top: Vec<(u32, u32, u32)> = Vec::new();
    let mut top_zero: Vec<(u32, u32)> = Vec::new();
    for (
        row_max,
        dx,
        dy,
        zero,
        zero_dx,
        sum,
        above,
        rows,
        mut rows_top,
        mut rows_zero,
    ) in partials
    {
        zero_sum += sum;
        zero_above_one += above;
        deterministic += rows;
        if zero > best_zero.0 {
            best_zero = (zero, zero_dx);
        }
        if row_max > best.0 {
            best = (row_max, dx, dy);
        }
        top.append(&mut rows_top);
        top_zero.append(&mut rows_zero);
    }
    top.sort_unstable_by(|a, b| b.cmp(a));
    top.truncate(4);
    top_zero.sort_unstable_by(|a, b| b.cmp(a));
    top_zero.truncate(4);
    let rows = (size - 1) as u64;
    DdtSummary {
        max_offdiagonal_count: best.0,
        arg_dx: best.1,
        arg_dy: best.2,
        max_zero_count: best_zero.0,
        zero_arg_dx: best_zero.1,
        zero_mean_x1024: if rows > 0 { zero_sum * 1024 / rows } else { 0 },
        zero_above_one,
        deterministic_rows: deterministic,
        top: [
            top.first().copied().unwrap_or((0, 0, 0)),
            top.get(1).copied().unwrap_or((0, 0, 0)),
            top.get(2).copied().unwrap_or((0, 0, 0)),
            top.get(3).copied().unwrap_or((0, 0, 0)),
        ],
        top_zero: [
            top_zero.first().copied().unwrap_or((0, 0)),
            top_zero.get(1).copied().unwrap_or((0, 0)),
            top_zero.get(2).copied().unwrap_or((0, 0)),
            top_zero.get(3).copied().unwrap_or((0, 0)),
        ],
    }
}

// ---------------------------------------------------------------------------
// Exact LAT via fast Walsh-Hadamard transform.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct LatSummary {
    /// Largest `|W(a, b)|` over nontrivial masks `a != 0` and `b != 0`.
    max_abs: i64,
    arg_input_mask: u32,
    arg_output_mask: u32,
    entries_at_max: u64,
    /// Rows `b != 0` whose input-mask maximum is attained at `a = 0`. For a
    /// bijection this is always true and only signals that `b = 0` is the
    /// trivial direction, so the count is reported for completeness.
    rows_with_full_correlation: u64,
}

fn walsh_hadamard(buffer: &mut [i64]) {
    let n = buffer.len();
    let mut half = 1;
    while half < n {
        let mut base = 0;
        while base < n {
            for index in base..base + half {
                let a = buffer[index];
                let b = buffer[index + half];
                buffer[index] = a + b;
                buffer[index + half] = a - b;
            }
            base += half * 2;
        }
        half *= 2;
    }
}

fn lat(map: &(dyn Fn(u32) -> u32 + Sync), width: u32, threads: usize) -> LatSummary {
    let size = 1usize << width;
    let full = size as i64;
    let ranges = split_ranges(size, threads);
    let partials: Vec<(i64, u32, u32, u64, u64)> = std::thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .into_iter()
            .map(|(lo, hi)| {
                let map = &*map;
                scope.spawn(move || {
                    let mut buffer = vec![0i64; size];
                    let mut best = 0i64;
                    let mut arg_a = 0u32;
                    let mut arg_b = 0u32;
                    let mut entries = 0u64;
                    let mut full_rows = 0u64;
                    for b in lo..hi {
                        let b32 = b as u32;
                        for x in 0..size {
                            let parity = (map(x as u32) & b32).count_ones() & 1;
                            buffer[x] = if parity == 0 { 1 } else { -1 };
                        }
                        walsh_hadamard(&mut buffer);
                        // `a = 0` is the trivial input mask and is excluded.
                        for a in 1..size {
                            let value = buffer[a].abs();
                            if value > best {
                                best = value;
                                arg_a = a as u32;
                                arg_b = b32;
                                entries = 1;
                            } else if value == best && best > 0 {
                                entries += 1;
                            }
                        }
                        if buffer[0].unsigned_abs() as i64 == full {
                            full_rows += 1;
                        }
                    }
                    (best, arg_a, arg_b, entries, full_rows)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("lat worker panicked"))
            .collect()
    });

    let mut summary = LatSummary {
        max_abs: 0,
        arg_input_mask: 0,
        arg_output_mask: 0,
        entries_at_max: 0,
        rows_with_full_correlation: 0,
    };
    for (best, arg_a, arg_b, entries, full_rows) in partials {
        summary.rows_with_full_correlation += full_rows;
        if best > summary.max_abs {
            summary = LatSummary {
                max_abs: best,
                arg_input_mask: arg_a,
                arg_output_mask: arg_b,
                entries_at_max: entries,
                rows_with_full_correlation: summary.rows_with_full_correlation,
            };
        } else if best == summary.max_abs && best > 0 {
            summary.entries_at_max += entries;
        }
    }
    summary
}

// ---------------------------------------------------------------------------
// Key independence of the DDT and the absolute LAT.
// ---------------------------------------------------------------------------

/// `F(x, k, c) = H((x ^ k) + c)` where `H` does not depend on `k`.
///
/// For a fixed key `k`, the map `x -> x ^ k` is a bijection that leaves every
/// XOR difference `dx` unchanged, so `DDT[dx][dy]` is identical for every
/// round key: the difference distribution table is key-independent.
///
/// For the linear table, substituting `u = x ^ k` gives
/// `<a, x ^ H(u)> = <a, u ^ k> ^ <a, H(u)>`, so the correlation picks up the
/// factor `(-1)^<a,k>`. The **absolute** correlation is therefore also
/// key-independent, and only its sign changes with the key.
///
/// This routine verifies both claims numerically instead of trusting the
/// algebra.
fn check_key_independence(width: u32, key: u32, constant: u32) -> (bool, bool) {
    let keyed = move |x: u32| round_w(x, key, constant, width);
    let keyed_summary = ddt(&keyed, width, 1);
    let zero_summary = ddt(&move |x| round_w(x, 0, constant, width), width, 1);
    let ddt_equal = keyed_summary.max_offdiagonal_count == zero_summary.max_offdiagonal_count
        && keyed_summary.max_zero_count == zero_summary.max_zero_count
        && keyed_summary.deterministic_rows == zero_summary.deterministic_rows;
    let keyed_lat = lat(&keyed, width, 1);
    let zero_lat = lat(&move |x| round_w(x, 0, constant, width), width, 1);
    let lat_equal = keyed_lat.max_abs == zero_lat.max_abs;
    (ddt_equal, lat_equal)
}

// ---------------------------------------------------------------------------
// Exact trail activity through the v0.3 four-branch outer network.
// ---------------------------------------------------------------------------

/// F-input activity bits of the four slots for a difference-activity pattern.
#[inline(always)]
fn slot_activity(pattern: u8) -> u8 {
    let d0 = (pattern >> 0) & 1;
    let d1 = (pattern >> 1) & 1;
    let d2 = (pattern >> 2) & 1;
    let d3 = (pattern >> 3) & 1;
    (d1 ^ d2 ^ d3)
        | ((d0 ^ d2 ^ d3) << 1)
        | ((d1 ^ d0 ^ d3) << 2)
        | ((d2 ^ d1 ^ d0) << 3)
}

/// One outer round under the *optimistic* screen model.
///
/// `F` is a permutation, so an active F evaluation can never return a zero
/// output difference: the zero column of the DDT is exactly empty. The only
/// freedom an attacker has is the *value* of a nonzero output difference, and
/// the screen grants the most favourable value for free: a slot output that
/// happens to equal the current word difference annihilates that word.
///
/// Because that annihilation is granted optimistically, the resulting activity
/// count is a lower bound on the true minimum, which is the safe direction for
/// a screen.
#[inline(always)]
fn advance(pattern: u8, annihilate: u8) -> u8 {
    let e = slot_activity(pattern);
    let mut next = 0u8;
    for slot in 0..4usize {
        let bit = 1u8 << slot;
        let current_active = (pattern & bit) != 0;
        let input_active = (e & bit) != 0;
        let next_active = if input_active {
            // F ran on a nonzero input, so its output difference is nonzero.
            // The word difference `d ^ f` is then zero only when `d` was
            // already active and `f` happens to equal `d` exactly.
            !(current_active && (annihilate & bit) != 0)
        } else {
            // F ran on a zero input, so the word difference passes through.
            current_active
        };
        if next_active {
            next |= bit;
        }
    }
    next
}

/// Minimum number of active F evaluations over `rounds` rounds for a trail that
/// starts and ends with a nonzero block difference. Exact dynamic program over
/// the 16 activity patterns; no sampling and no heuristic pruning.
fn minimum_activity(rounds: usize, start: u8) -> (usize, bool) {
    const INF: usize = usize::MAX / 4;
    let mut cost = [INF; 16];
    cost[start as usize] = 0;
    for _ in 0..rounds {
        let mut next_cost = [INF; 16];
        for pattern in 1u8..16 {
            if cost[pattern as usize] == INF {
                continue;
            }
            let activity = (slot_activity(pattern) & 0b1111).count_ones() as usize;
            for annihilate in 0u8..16 {
                let target = advance(pattern, annihilate);
                if target == 0 {
                    // A dead difference can never be revived: with all words
                    // inactive every later F call has a zero input.
                    continue;
                }
                let candidate = cost[pattern as usize] + activity;
                if candidate < next_cost[target as usize] {
                    next_cost[target as usize] = candidate;
                }
            }
        }
        cost = next_cost;
    }
    let best = (1u8..16)
        .map(|pattern| cost[pattern as usize])
        .min()
        .unwrap_or(INF);
    (best, best != INF)
}

fn split_ranges(size: usize, threads: usize) -> Vec<(usize, usize)> {
    let threads = threads.max(1);
    let chunk = size.div_ceil(threads);
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < size {
        let end = (start + chunk).min(size);
        ranges.push((start, end));
        start = end;
    }
    ranges
}

// ---------------------------------------------------------------------------
// Cross-check against the shipped implementation.
// ---------------------------------------------------------------------------

fn cross_check(iterations: u64) -> bool {
    let mut state = 0x243F_6A88_85A3_08D3u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..iterations {
        let x = next() as u32;
        let k = next() as u32;
        let round = (next() % 24) as usize;
        let slot = (next() % 4) as usize;
        let constant = PRIMES[round] ^ SLOT[slot];
        if round_function(x, k, constant) != riak::v2::round_function(x, k, constant) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Exact truncated-differential screen on a reduced-width block.
// ---------------------------------------------------------------------------

struct TruncatedResult {
    total: u64,
    weight_histogram: [u64; 5],
    dead: u64,
}

fn truncated_screen(
    round_keys: &[u32; 24],
    width: u32,
    pattern: u8,
    diff: [u32; 4],
    progress_every: u64,
) -> TruncatedResult {
    let m = mask_w(width);
    let size = 1u64 << (4 * width);
    let mut histogram = [0u64; 5];
    let mut dead = 0u64;
    let d = [
        diff[0] & m,
        diff[1] & m,
        diff[2] & m,
        diff[3] & m,
    ];
    for x in 0..size {
        let mut base = [0u32; 4];
        for word in 0..4usize {
            base[word] = ((x >> (word as u32 * width)) & m as u64) as u32;
        }
        let mut left = base;
        let mut right = [base[0] ^ d[0], base[1] ^ d[1], base[2] ^ d[2], base[3] ^ d[3]];
        encrypt_block_w(round_keys, &mut left, width);
        encrypt_block_w(round_keys, &mut right, width);
        let mut weight = 0u32;
        for word in 0..4usize {
            if (left[word] ^ right[word]) & m != 0 {
                weight += 1;
            }
        }
        histogram[weight as usize] += 1;
        if weight == 0 {
            dead += 1;
        }
        if progress_every > 0 && x % progress_every == 0 && x > 0 {
            eprint!("\r  pattern 0x{pattern:X}: {x}/{size} pairs");
        }
    }
    if progress_every > 0 {
        eprint!("\r{:width$}", "", width = 60);
    }
    TruncatedResult {
        total: size,
        weight_histogram: histogram,
        dead,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Every step of the round function is a permutation, so the zero column of
    /// the DDT must be empty and no nonzero input difference may map to a
    /// single output difference.
    #[test]
    fn round_function_ddt_has_empty_zero_column() {
        let width = 8;
        let map = |x: u32| round_w(x, 0, 2, width);
        let summary = ddt(&map, width, 1);
        assert_eq!(summary.max_zero_count, 0, "a permutation cannot absorb");
        assert_eq!(summary.zero_above_one, 0);
        assert_eq!(summary.deterministic_rows, 0, "no nonzero dx may be deterministic");
    }

    /// The DDT of a permutation of size 2^w has row sums equal to 2^w. Checking
    /// the total count over a row guards against off-by-one errors in the
    /// enumeration and the counter reset.
    #[test]
    fn ddt_rows_sum_to_table_size() {
        let width = 6;
        let size = 1u32 << width;
        let map = |x: u32| round_w(x, 0x5A5A, 3, width);
        for dx in 0..size {
            let mut counts = vec![0u32; size as usize];
            for x in 0..size {
                let dy = map(x) ^ map(x ^ dx);
                counts[dy as usize] += 1;
            }
            let total: u32 = counts.iter().sum();
            assert_eq!(total, size, "row {dx} did not sum to {size}");
        }
    }

    /// `F(x,k,c) = H((x ^ k) + c)`, so the DDT and the absolute LAT cannot
    /// depend on the round key. This is the property that lets one reduced-width
    /// measurement stand in for every round key.
    #[test]
    fn ddt_and_absolute_lat_are_key_independent() {
        let width = 8;
        for (key, constant) in [(0u32, 2u32), (0xFFFF_FFFF, 0x1357_9BDF), (0xA5A5_5A5A, 0x2468_ACE0)]
        {
            let (ddt_equal, lat_equal) = check_key_independence(width, key, constant);
            assert!(ddt_equal, "DDT changed with key 0x{key:08X}");
            assert!(lat_equal, "|LAT| changed with key 0x{key:08X}");
        }
    }

    /// Parseval for the Walsh-Hadamard transform: for any `+/-1` sequence `f`
    /// of length `N`, the squared coefficients sum to `N^2`, because
    /// `sum_a W(a)^2 = N * sum_x f(x)^2 = N * N`. This validates the transform
    /// and the `+/-1` construction. For `N = 64` the total must be `4096`.
    #[test]
    fn lat_satisfies_parseval() {
        let width = 6;
        let size = 1usize << width;
        let map = |x: u32| round_w(x, 0, 11, width);
        let expected = (size * size) as i64;
        for b in 1..size {
            let mut buffer: Vec<i64> = (0..size)
                .map(|x| {
                    if (map(x as u32) & b as u32).count_ones() & 1 == 0 {
                        1
                    } else {
                        -1
                    }
                })
                .collect();
            walsh_hadamard(&mut buffer);
            let sum_of_squares: i64 = buffer.iter().map(|value| value * value).sum();
            assert_eq!(sum_of_squares, expected, "Parseval failed for mask b={b}");
        }
    }

    /// The 32-bit specification copy must agree with the shipped implementation
    /// on whole blocks, which also validates the key schedule and the outer
    /// network re-derivation.
    #[test]
    fn specification_block_cipher_matches_library() {
        assert!(cross_check_block(64));
    }

    #[test]
    fn specification_round_function_matches_library() {
        assert!(cross_check(10_000));
    }

    /// A single-word difference must diffuse into every word within a few
    /// rounds, and no 24-round trail may stay cheap. The DP is a lower bound, so
    /// a healthy cipher keeps the minimum far above the round count.
    #[test]
    fn trail_activity_lower_bound_is_large() {
        for start in 1u8..16 {
            let (activity, reachable) = minimum_activity(24, start);
            assert!(reachable, "pattern 0x{start:X} has no surviving trail");
            assert!(
                activity >= 24,
                "pattern 0x{start:X} admits only {activity} active F calls"
            );
        }
    }

    /// The truncated screen must never observe a fully dead difference: the
    /// round function is a permutation, so a nonzero block difference cannot
    /// collapse to zero everywhere.
    #[test]
    fn reduced_block_difference_never_dies() {
        let width = 3;
        let round_keys = key_schedule_v3([0x1357_9BDF; 16], DOMAIN_DEFAULT);
        let distinct = [0b000101u32, 0b011011, 0b110111, 0b111111];
        for pattern in 1u8..16 {
            let mut diff = [0u32; 4];
            for slot in 0..4usize {
                if (pattern >> slot) & 1 == 1 {
                    diff[slot] = distinct[slot] & mask_w(width);
                }
            }
            let result = truncated_screen(&round_keys, width, pattern, diff, 0);
            assert_eq!(result.dead, 0, "pattern 0x{pattern:X} produced a dead difference");
            assert_eq!(
                result.weight_histogram.iter().sum::<u64>(),
                result.total
            );
        }
    }
}

struct Config {
    width: u32,
    threads: usize,
    round: usize,
    run_ddt: bool,
    run_lat: bool,
    cross_check_iterations: u64,
    cross_check_blocks: u64,
    assert_diff_log2: Option<u32>,
    assert_zero_log2: Option<u32>,
    assert_corr_log2: Option<u32>,
    include_layers: bool,
    reduced_width: Option<u32>,
    equal_values: bool,
    check_key_independence: bool,
}

const USAGE: &str = "\
riak-ddt-probe -- exact reduced-width DDT/LAT probe for the RIAK round bijection

USAGE:
    riak-ddt-probe [OPTIONS]

OPTIONS:
    --width N            reduced word width, 4..=20 (default 12)
    --threads N          worker threads (default: available parallelism)
    --round N            round whose slot constants are probed, 0..=23 (default 0)
    --skip-ddt           do not run the differential table
    --skip-lat           do not run the linear table
    --layers             also probe the individual linear/multiply/add layers
    --cross-check N      random round-function cross-check cases (default 100000)
    --cross-check-blocks N  random whole-block cross-check cases (default 256)
    --reduced-block W    run the exact truncated screen with W bits per word (1..=6)
    --equal-values       use one shared difference value in every active word
                         instead of distinct per-word values
    --key-independence   verify numerically that the DDT and |LAT| do not
                         depend on the round key
    --assert-diff-log2 N fail unless every probed map has DDT max off-diagonal probability <= 2^-N
    --assert-zero-log2 N fail unless every probed map has DDT absorption probability <= 2^-N
    --assert-corr-log2 N fail unless every probed map has LAT |correlation| <= 2^-N
    -h, --help           show this help

EXIT STATUS:
    0  probe completed and every requested assertion held
    1  an assertion failed
    2  invalid arguments
";

fn parse_args() -> Result<Config, String> {
    let available = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let mut config = Config {
        width: 12,
        threads: available,
        round: 0,
        run_ddt: true,
        run_lat: true,
        cross_check_iterations: 100_000,
        cross_check_blocks: 256,
        assert_diff_log2: None,
        assert_zero_log2: None,
        assert_corr_log2: None,
        include_layers: false,
        reduced_width: None,
        equal_values: false,
        check_key_independence: false,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].clone();
        let value = |index: &mut usize| -> Result<String, String> {
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match args[index].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--width" => {
                config.width = value(&mut index)?
                    .parse()
                    .map_err(|_| "invalid --width".to_string())?;
            }
            "--threads" => {
                config.threads = value(&mut index)?
                    .parse::<usize>()
                    .map_err(|_| "invalid --threads".to_string())?
                    .max(1);
            }
            "--round" => {
                config.round = value(&mut index)?
                    .parse()
                    .map_err(|_| "invalid --round".to_string())?;
            }
            "--skip-ddt" => config.run_ddt = false,
            "--skip-lat" => config.run_lat = false,
            "--layers" => config.include_layers = true,
            "--equal-values" => config.equal_values = true,
            "--key-independence" => config.check_key_independence = true,
            "--reduced-block" => {
                config.reduced_width = Some(
                    value(&mut index)?
                        .parse()
                        .map_err(|_| "invalid --reduced-block".to_string())?,
                );
            }
            "--cross-check-blocks" => {
                config.cross_check_blocks = value(&mut index)?
                    .parse()
                    .map_err(|_| "invalid --cross-check-blocks".to_string())?;
            }
            "--cross-check" => {
                config.cross_check_iterations = value(&mut index)?
                    .parse()
                    .map_err(|_| "invalid --cross-check".to_string())?;
            }
            "--assert-diff-log2" => {
                config.assert_diff_log2 = Some(
                    value(&mut index)?
                        .parse()
                        .map_err(|_| "invalid --assert-diff-log2".to_string())?,
                );
            }
            "--assert-zero-log2" => {
                config.assert_zero_log2 = Some(
                    value(&mut index)?
                        .parse()
                        .map_err(|_| "invalid --assert-zero-log2".to_string())?,
                );
            }
            "--assert-corr-log2" => {
                config.assert_corr_log2 = Some(
                    value(&mut index)?
                        .parse()
                        .map_err(|_| "invalid --assert-corr-log2".to_string())?,
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
        index += 1;
    }
    if !(4..=20).contains(&config.width) {
        return Err("--width must be between 4 and 20".to_string());
    }
    if config.round >= 24 {
        return Err("--round must be between 0 and 23".to_string());
    }
    if !config.run_ddt && !config.run_lat && config.reduced_width.is_none() {
        return Err("nothing to do: both tables are skipped".to_string());
    }
    if let Some(width) = config.reduced_width {
        if !(1..=6).contains(&width) {
            return Err("--reduced-block must be between 1 and 6".to_string());
        }
    }
    Ok(config)
}

fn log2_estimate(numerator: u64, denominator: u64) -> f64 {
    if numerator == 0 {
        return f64::NEG_INFINITY;
    }
    (numerator as f64).log2() - (denominator as f64).log2()
}

/// Reference maximum count of the DDT of a uniformly random permutation.
///
/// For a fixed `dx != 0` the `2^(w-1)` pairs `{x, x ^ dx}` each contribute one
/// output difference, and under the random-permutation model those values are
/// spread over `2^w` outcomes, so every entry of a DDT row is approximately
/// Poisson with mean `2^(w-1) / 2^w = 1/2`. The expected maximum over all
/// `2^w * (2^w - 1)` off-diagonal entries is therefore approximately
/// `2 * ln(2^(2w)) = 4 w ln 2`.
///
/// This is a theoretical reference, not a measurement. It is used only to say
/// whether a measured maximum is in the range a random permutation would also
/// produce, and it carries no security meaning for RIAK itself.
fn random_permutation_reference(width: u32) -> f64 {
    4.0 * width as f64 * 2f64.ln()
}

/// Reference maximum `|W|` of the LAT of a uniformly random permutation.
///
/// For each output mask the `2^w` Walsh coefficients of a `+/-1` sequence behave
/// like scaled standard normals, so `|W|` has scale `sqrt(2^w)` and the maximum
/// over `2^(2w)` entries is approximately `sqrt(2^w) * sqrt(ln(2^(2w)))`.
fn random_permutation_lat_reference(width: u32) -> f64 {
    let size = 2f64.powi(width as i32);
    (size * (2f64 * size).ln()).sqrt()
}

fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    println!("RIAK reduced-width differential/linear probe");
    println!("research tool: not a security proof");
    if config.cross_check_iterations > 0 {
        println!(
            "cross-checking the specification copy against riak::v2::round_function ({} random cases)",
            config.cross_check_iterations
        );
        if !cross_check(config.cross_check_iterations) {
            eprintln!("FAIL: specification copy disagrees with the shipped implementation");
            return ExitCode::FAILURE;
        }
        println!("cross-check: OK");
    }
    if config.cross_check_blocks > 0 {
        println!(
            "cross-checking the full specification cipher (key schedule + outer network) against riak::v3::RiakV3 ({} random cases)",
            config.cross_check_blocks
        );
        if !cross_check_block(config.cross_check_blocks) {
            eprintln!("FAIL: specification block cipher disagrees with the shipped implementation");
            return ExitCode::FAILURE;
        }
        println!("block cross-check: OK");
    }
    println!("width: {} bit(s), threads: {}", config.width, config.threads);
    println!("round constants: round {}", config.round);
    println!();

    struct Probe {
        name: String,
        map: Box<dyn Fn(u32) -> u32 + Sync>,
    }

    let width = config.width;
    let mut probes: Vec<Probe> = vec![Probe {
        name: "core (k=0, c=0)".to_string(),
        map: Box::new(move |x| round_w(x, 0, 0, width)),
    }];
    for slot in 0..4usize {
        let constant = PRIMES[config.round] ^ SLOT[slot];
        probes.push(Probe {
            name: format!("slot{slot} (c=0x{constant:08X})"),
            map: Box::new(move |x| round_w(x, 0, constant, width)),
        });
    }
    if config.include_layers {
        probes.push(Probe {
            name: "layer mix_a".to_string(),
            map: Box::new(move |x| {
                let m = mask_w(width);
                let mut t = x & m;
                t ^= t >> 7;
                t = rotl_w(t, 11, width);
                (t ^ (t << 9)) & m
            }),
        });
        probes.push(Probe {
            name: "layer mix_b".to_string(),
            map: Box::new(move |x| {
                let m = mask_w(width);
                let mut t = x & m;
                t ^= t >> 5;
                t = rotl_w(t, 7, width);
                (t ^ (t << 13)) & m
            }),
        });
        probes.push(Probe {
            name: "layer mix_c".to_string(),
            map: Box::new(move |x| {
                let m = mask_w(width);
                let mut t = x & m;
                t ^= t >> 17;
                t = rotl_w(t, 19, width);
                (t ^ (t << 15)) & m
            }),
        });
        probes.push(Probe {
            name: "layer mul_a".to_string(),
            map: Box::new(move |x| x.wrapping_mul(MUL_A) & mask_w(width)),
        });
        probes.push(Probe {
            name: "layer add_a".to_string(),
            map: Box::new(move |x| x.wrapping_add(ADD_A) & mask_w(width)),
        });
    }

    let size = 1u64 << config.width;
    let mut worst_diff_count = 0u64;
    let mut worst_corr_abs = 0u64;
    let mut worst_zero_count = 0u64;
    for probe in &probes {
        println!("--- {} ---", probe.name);
        if config.run_ddt {
            let summary = ddt(probe.map.as_ref(), config.width, config.threads);
            worst_diff_count = worst_diff_count.max(summary.max_offdiagonal_count as u64);
            worst_zero_count = worst_zero_count.max(summary.max_zero_count as u64);
            let reference = random_permutation_reference(config.width);
            let ratio = summary.max_offdiagonal_count as f64 / reference;
            println!(
                "  DDT: max off-diagonal count {}/{} = 2^{:.3} at dx=0x{:X} -> dy=0x{:X}",
                summary.max_offdiagonal_count,
                size,
                log2_estimate(summary.max_offdiagonal_count as u64, size),
                summary.arg_dx,
                summary.arg_dy
            );
            println!(
                "  DDT: ratio to the random-permutation reference ~{:.0} ({:.1}x) [reference is a Poisson extreme-value estimate, not a guarantee]",
                reference, ratio
            );
            println!(
                "  DDT: zero column (absorption) max {}/{} = 2^{:.3} at dx=0x{:X}, mean {}/1024, rows above 1: {}",
                summary.max_zero_count,
                size,
                log2_estimate(summary.max_zero_count as u64, size),
                summary.zero_arg_dx,
                summary.zero_mean_x1024,
                summary.zero_above_one
            );
            println!(
                "  DDT: input-difference rows containing a probability-1 pair: {} of {}",
                summary.deterministic_rows,
                size - 1
            );
            println!("  DDT: strongest off-diagonal rows (count, dx, dy):");
            for (count, dx, dy) in summary.top {
                if count == 0 {
                    continue;
                }
                println!(
                    "    {count:>10}  dx=0x{dx:X}  dy=0x{dy:X}  (2^{:.3})",
                    log2_estimate(count as u64, size)
                );
            }
            println!("  DDT: strongest zero-column rows (count, dx):");
            for (count, dx) in summary.top_zero {
                if count == 0 {
                    continue;
                }
                println!("    {count:>10}  dx=0x{dx:X}");
            }
        }
        if config.run_lat {
            let summary = lat(probe.map.as_ref(), config.width, config.threads);
            worst_corr_abs = worst_corr_abs.max(summary.max_abs as u64);
            let reference = random_permutation_lat_reference(config.width);
            let ratio = summary.max_abs as f64 / reference;
            println!(
                "  LAT: max |W| {}/{} = 2^{:.3} (bias 2^{:.3}) at a=0x{:X} b=0x{:X}",
                summary.max_abs,
                size,
                log2_estimate(summary.max_abs as u64, size),
                log2_estimate(summary.max_abs as u64, size) - 1.0,
                summary.arg_input_mask,
                summary.arg_output_mask
            );
            println!(
                "  LAT: ratio to the random-permutation reference ~{:.0} ({:.1}x) [Gaussian extreme-value estimate]",
                reference, ratio
            );
            println!(
                "  LAT: table entries at the maximum: {}",
                summary.entries_at_max
            );
        }
        println!();
    }

    println!("--- v0.3 outer network: exact 24-round trail activity (lower bound) ---");
    println!("  F is a permutation, so an active evaluation never returns a zero difference;");
    println!("  the screen only grants the attacker the most favourable nonzero output value.");
    let mut global_minimum = usize::MAX;
    for start in 1u8..16 {
        let (activity, reachable) = minimum_activity(24, start);
        let note = if reachable { "" } else { " (no surviving trail)" };
        println!(
            "  start activity 0x{start:X} (weight {}) -> minimum active F evaluations: {activity}{note}",
            start.count_ones()
        );
        if reachable {
            global_minimum = global_minimum.min(activity);
        }
    }
    if global_minimum == usize::MAX {
        println!("  no nonzero difference survives 24 rounds under this model");
    } else {
        println!("  smallest minimum across all nonzero starts: {global_minimum}");
    }
    if config.run_ddt && worst_diff_count > 0 && global_minimum != usize::MAX {
        let probability_log2 = log2_estimate(worst_diff_count, size);
        println!(
            "  propagation screen: worst measured single-step p = 2^{probability_log2:.3}, so the cheapest"
        );
        println!(
            "  trail shape is at most 2^{:.3} ({} active F calls)",
            probability_log2 * global_minimum as f64,
            global_minimum
        );
    }
    println!("  note: per-trail only; differential-hull accumulation is not bounded here");
    println!();

    if config.check_key_independence && config.run_ddt && config.run_lat {
        println!("--- DDT / |LAT| key independence ---");
        println!("  F(x,k,c) = H((x ^ k) + c); x -> x ^ k preserves every XOR difference,");
        println!("  so DDT[dx][dy] must be identical for every round key, and the LAT");
        println!("  correlation may only change sign through the factor (-1)^<a,k>.");
        let mut all_ddt = true;
        let mut all_lat = true;
        for (key, constant) in [
            (0x0000_0000u32, 0x0000_0002u32),
            (0xFFFF_FFFF, 0x1357_9BDF),
            (0xA5A5_5A5A, 0x2468_ACE0),
            (0x5A5A_A5A5, 0xFEDC_BA98),
        ] {
            let (ddt_equal, lat_equal) = check_key_independence(config.width, key, constant);
            println!(
                "  k=0x{key:08X} c=0x{constant:08X}: DDT identical {ddt_equal}, |LAT| identical {lat_equal}"
            );
            all_ddt &= ddt_equal;
            all_lat &= lat_equal;
        }
        if !(all_ddt && all_lat) {
            eprintln!("FAIL: key independence does not hold");
            return ExitCode::FAILURE;
        }
        println!("  key independence: confirmed numerically");
        println!();
    }

    if let Some(reduced) = config.reduced_width {
        println!("--- exact truncated-differential screen, {reduced} bit(s) per word ---");
        let key = [0x1357_9BDFu32; 16];
        let round_keys = key_schedule_v3(key, DOMAIN_DEFAULT);
        // Distinct nonzero per-word values avoid the case where the same value
        // repeats across words and cancels in the XOR of the other three.
        let distinct: [u32; 4] = [0b000101, 0b011011, 0b110111, 0b111111];
        let m = mask_w(reduced);
        let size = 1u64 << (4 * reduced);
        let progress = if size > 1_000_000 { size / 20 } else { 0 };
        println!(
            "  enumerating all {size} reduced inputs per pattern; a random permutation would give"
        );
        println!("  P[weight k] = C(4,k)/16 for k >= 1 and P[weight 0] = 0");
        let mut worst_dead = 0f64;
        for pattern in 1u8..16 {
            let mut diff = [0u32; 4];
            for slot in 0..4usize {
                let bit = (pattern >> slot) & 1;
                if bit == 1 {
                    diff[slot] = if config.equal_values {
                        1
                    } else {
                        distinct[slot]
                    } & m;
                }
            }
            let result = truncated_screen(&round_keys, reduced, pattern, diff, progress);
            let weights: Vec<String> = (0..5)
                .map(|k| {
                    let count = result.weight_histogram[k];
                    format!(
                        "{k}:{}/{}={:.5}",
                        count,
                        result.total,
                        count as f64 / result.total as f64
                    )
                })
                .collect();
            let dead_ratio = result.dead as f64 / result.total as f64;
            worst_dead = worst_dead.max(dead_ratio);
            println!(
                "  pattern 0x{pattern:X} (weight {}) -> {}",
                pattern.count_ones(),
                weights.join("  ")
            );
        }
        println!(
            "  worst P[output difference completely dead] = {worst_dead:.6} (random permutation: 0)"
        );
        println!();
    }

    let mut failures: Vec<String> = Vec::new();
    if let (Some(limit), true) = (config.assert_diff_log2, config.run_ddt) {
        let allowed = if limit <= config.width {
            1u64 << (config.width - limit)
        } else {
            0
        };
        if worst_diff_count > allowed {
            failures.push(format!(
                "DDT max probability 2^{:.3} exceeds the required 2^-{limit}",
                log2_estimate(worst_diff_count, size)
            ));
        }
    }
    if let (Some(limit), true) = (config.assert_zero_log2, config.run_ddt) {
        let allowed = if limit <= config.width {
            1u64 << (config.width - limit)
        } else {
            0
        };
        if worst_zero_count > allowed {
            failures.push(format!(
                "DDT absorption max 2^{:.3} exceeds the required 2^-{limit}",
                log2_estimate(worst_zero_count, size)
            ));
        }
    }
    if let (Some(limit), true) = (config.assert_corr_log2, config.run_lat) {
        let allowed = if limit <= config.width {
            1u64 << (config.width - limit)
        } else {
            0
        };
        if worst_corr_abs > allowed {
            failures.push(format!(
                "LAT max correlation 2^{:.3} exceeds the required 2^-{limit}",
                log2_estimate(worst_corr_abs, size)
            ));
        }
    }
    if failures.is_empty() {
        println!("assertions: PASS");
        println!("done");
        ExitCode::SUCCESS
    } else {
        for failure in &failures {
            println!("ASSERTION FAILED: {failure}");
        }
        ExitCode::FAILURE
    }
}
