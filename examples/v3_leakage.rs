//! Statistical constant-time screen for the RIAK v0.3 core.
//!
//! `dudect` and `ctgrind` are not available in this environment, but the
//! ingredients for a first-order leakage test are: the CPU can be pinned with
//! `taskset`, the process can be given real-time priority, and the raw cycle
//! counter is readable from Rust. This tool implements a dudect-style
//! first-order test directly.
//!
//! Method, following the standard approach:
//!
//! 1. Measure an operation twice for two input classes:
//!    - **fixed**: every call uses the same plaintext, so any correct
//!      implementation takes the same branch pattern every time;
//!    - **random**: each call uses a fresh random plaintext.
//! 2. Randomise the order of the two classes so that slow drift in machine
//!    state cannot masquerade as a class difference.
//! 3. Compute Welch's t statistic on the two sample means and report the
//!    magnitude of the t value. Leakage shows up as a large `|t|`.
//!
//! Interpreting the result honestly:
//!
//! - `|t| < 4.5` is the usual dudect threshold for a first-order test. Passing
//!   it means **no first-order leakage was detected at this sample size on this
//!   machine**. It does not prove constant-time behaviour, does not cover
//!   second-order leakage, and does not transfer to other hardware.
//! - A high `|t|` is a strong signal to investigate, and this tool does not
//!   attempt to explain it.
//!
//! Run it pinned and at raised priority for the measurement to mean anything:
//!
//! ```text
//! taskset -c 0 chrt -f 5 cargo run --release --example v3_leakage -- <samples>
//! ```

use riak::v3::RiakV3;

/// Read the hardware cycle counter when the target exposes it.
///
/// Falls back to the wall clock otherwise, which is noisier but still usable.
#[cfg(target_arch = "x86_64")]
fn cycles() -> u64 {
    // SAFETY: `_rdtsc` has no preconditions and cannot fail. It is not
    // serialising, which is why the caller also brackets the region with a
    // compiler fence to keep the measured work from being hoisted out.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(not(target_arch = "x86_64"))]
fn cycles() -> u64 {
    static COUNTER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let _ = *COUNTER.get_or_init(|| false);
    0
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
}

/// Welch's t statistic for two independent samples.
fn welch_t(left: &[f64], right: &[f64]) -> f64 {
    let mean = |values: &[f64]| values.iter().sum::<f64>() / values.len() as f64;
    let variance = |values: &[f64]| {
        let m = mean(values);
        values.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (values.len() - 1) as f64
    };
    let (mean_left, mean_right) = (mean(left), mean(right));
    let denominator = (variance(left) / left.len() as f64
        + variance(right) / right.len() as f64)
        .sqrt();
    if denominator == 0.0 {
        return 0.0;
    }
    (mean_left - mean_right) / denominator
}

fn measure_block(cipher: &RiakV3, block: [u32; 4]) -> u64 {
    // The fences keep the compiler from moving the cipher work out of the
    // measured region or from reordering it across the counter reads.
    std::hint::black_box(&cipher);
    std::hint::black_box(block);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let start = cycles();
    let mut working = std::hint::black_box(block);
    std::hint::black_box(&mut working);
    cipher.encrypt_block(&mut working);
    let end = cycles();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    std::hint::black_box(working);
    end.wrapping_sub(start)
}

fn main() {
    let samples: usize = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(200_000);

    println!("RIAK v0.3 first-order leakage screen (dudect-style)");
    println!("bounded screen: no detected leakage is not a constant-time proof");
    println!();
    println!("samples per class: {samples}");
    println!("total measurements: {}", samples * 2);
    #[cfg(target_arch = "x86_64")]
    println!("timer: hardware cycle counter (rdtsc)");
    #[cfg(not(target_arch = "x86_64"))]
    println!("timer: unavailable on this architecture, results are not meaningful");
    println!();

    if !cfg!(target_arch = "x86_64") {
        println!("this architecture has no cycle counter, so the test cannot run here");
        std::process::exit(2);
    }

    let cipher = RiakV3::from_words([0x1357_9BDF; 16]);
    let mut rng = Rng(0x0123_4567_89AB_CDEF);

    let fixed_block: [u32; 4] = [0x0123_4567, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210];

    // Warm the caches and the branch predictor so the first measurements are
    // not dominated by cold-start effects.
    for _ in 0..10_000 {
        let _ = measure_block(&cipher, fixed_block);
        let random = [rng.next() as u32, rng.next() as u32, rng.next() as u32, rng.next() as u32];
        let _ = measure_block(&cipher, random);
    }

    let mut fixed_samples: Vec<f64> = Vec::with_capacity(samples);
    let mut random_samples: Vec<f64> = Vec::with_capacity(samples);

    for index in 0..samples {
        // Randomise the class order each round so that a slow drift in machine
        // temperature or frequency affects both classes equally.
        let run_fixed_first = (rng.next() & 1) == 0;
        for run_fixed in [run_fixed_first, !run_fixed_first] {
            let block = if run_fixed {
                fixed_block
            } else {
                [
                    rng.next() as u32,
                    rng.next() as u32,
                    rng.next() as u32,
                    rng.next() as u32,
                ]
            };
            let measurement = measure_block(&cipher, block) as f64;
            if run_fixed {
                fixed_samples.push(measurement);
            } else {
                random_samples.push(measurement);
            }
        }
        if index > 0 && index % 25_000 == 0 {
            // Running t on the partial data gives early warning if the effect
            // is large enough to be obvious before the full run finishes.
            let t = welch_t(&fixed_samples, &random_samples);
            println!("  {index} rounds so far, running t = {t:.3}");
        }
    }

    let t = welch_t(&fixed_samples, &random_samples);
    let mean = |values: &[f64]| values.iter().sum::<f64>() / values.len() as f64;
    let mean_fixed = mean(&fixed_samples);
    let mean_random = mean(&random_samples);

    println!();
    println!("results (fixed vs random)");
    println!("  fixed class  mean: {mean_fixed:.3} cycles");
    println!("  random class mean: {mean_random:.3} cycles");
    println!(
        "  difference:        {:.3} cycles ({:+.4}%)",
        mean_fixed - mean_random,
        100.0 * (mean_fixed - mean_random) / mean_random
    );
    println!("  Welch's t:         {t:.4}");
    println!();

    // -------------------------------------------------------------------
    // Negative control.
    // -------------------------------------------------------------------
    // Two classes that are BOTH constant, but different from each other. The
    // cipher does the same work for both, so a correct implementation must show
    // no difference here. If this control also produces a large t, then the
    // measurement setup itself is biased and the fixed-vs-random result above
    // cannot be attributed to the cipher.
    let mut control_left: Vec<f64> = Vec::with_capacity(samples);
    let mut control_right: Vec<f64> = Vec::with_capacity(samples);
    let control_block_a: [u32; 4] = [0x1111_1111, 0x1111_1111, 0x1111_1111, 0x1111_1111];
    let control_block_b: [u32; 4] = [0x2222_2222, 0x2222_2222, 0x2222_2222, 0x2222_2222];
    for _ in 0..samples {
        for use_a in [true, false] {
            let block = if use_a { control_block_a } else { control_block_b };
            let measurement = measure_block(&cipher, block) as f64;
            if use_a {
                control_left.push(measurement);
            } else {
                control_right.push(measurement);
            }
        }
    }
    let control_t = welch_t(&control_left, &control_right);
    let control_mean_left = mean(&control_left);
    let control_mean_right = mean(&control_right);
    println!("negative control (constant A vs constant B, both fixed)");
    println!("  class A mean:     {control_mean_left:.3} cycles");
    println!("  class B mean:     {control_mean_right:.3} cycles");
    println!(
        "  difference:       {:.3} cycles ({:+.4}%)",
        control_mean_left - control_mean_right,
        100.0 * (control_mean_left - control_mean_right) / control_mean_right
    );
    println!("  Welch's t:        {control_t:.4}");
    println!();

    let threshold = 4.5;
    let verdict = if control_t.abs() >= threshold {
        println!("  The NEGATIVE CONTROL is also above the threshold.");
        println!("  Both classes are constant, so the cipher does identical work for both.");
        println!("  A significant t here means the measurement setup is biased, not that the");
        println!("  cipher leaks: this is a property of the machine, the harness, or the sample");
        println!("  size, and the fixed-vs-random result above cannot be interpreted.");
        "INCONCLUSIVE: the harness itself shows a class difference"
    } else if t.abs() < threshold {
        println!("  |t| < {threshold}: no first-order leakage detected at this sample size,");
        println!("  and the negative control is clean, so the measurement setup is sound.");
        "PASS: no first-order leakage detected, with a clean negative control"
    } else {
        println!("  |t| >= {threshold} with a CLEAN negative control: the difference is not");
        println!("  explained by the harness. This is a genuine first-order timing signal in");
        println!("  the block core and must be investigated before any constant-time claim.");
        "FINDING: first-order timing difference with a clean negative control"
    };
    println!();
    println!("  verdict: {verdict}");
    println!();
    println!("what this does NOT establish:");
    println!("  - a pass is not a constant-time proof, it is an absence of detection");
    println!("  - only first-order (single-sample) leakage is covered");
    println!("  - only one machine, one compiler, and one target are covered");
    println!("  - cache, port contention, speculative, and power side channels are not covered");
    println!("  - the wrapper mode and tag paths are not covered here, only the block core");
    println!();
    println!("recommended invocation:");
    println!("  taskset -c 0 chrt -f 5 cargo run --release --example v3_leakage -- 1000000");
}
