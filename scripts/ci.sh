#!/usr/bin/env bash
set -euo pipefail

cargo check --all-targets
cargo check --all-targets --features legacy-v1
cargo test --release --all-targets
cargo test --release --features legacy-v1 --test cli_legacy
python3 simulator/riak_v2.py
python3 simulator/riak_v3.py
python3 simulator/generate_v3_vectors.py

# Fast deterministic screening runs; increase sample counts for a deeper audit.
cargo run --release --example v2_differential 65536
cargo run --release --example v2_full_linear 8192
cargo run --release --example v2_related 256
cargo run --release --example v2_trail_search 4096 10000 8
cargo run --release --example v3_sample -- wildanelis
cargo run --release --example v3_probe
cargo run --release --example v3_avalanche 128
cargo run --release --example v3_differential 4096
cargo run --release --example v3_linear_trail_search 2048 12
cargo run --release --example v3_linear_hull 2048 12 4
cargo run --release --example v3_full_linear 2048
cargo run --release --example v3_trail_search 2048 10000 4
cargo run --release --example v3_related 256
cargo run --release --example v3_key_schedule_analysis 256
cargo run --release --example v3_related_multibit 256
cargo run --release --example v3_timing
cargo run --release --example v3_bench
cargo run --release --example v3_mode_analysis

# Exact reduced-width DDT/LAT and trail-activity screen. The assertions are
# regression gates against the values recorded in docs/riak_v3_ddt_lat.md, not
# security claims. Full measurements are run manually at a higher width.
cargo test --release --manifest-path analysis/ddt-probe/Cargo.toml
cargo run --release --manifest-path analysis/ddt-probe/Cargo.toml -- \
  --width 12 --key-independence \
  --assert-diff-log2 4 --assert-zero-log2 1 --assert-corr-log2 2

# Repeatable static side-channel screen. Fails on integer division in the core
# or a secret-dependent branch. A pass is a screen on one toolchain, not a
# constant-time guarantee.
scripts/asm_audit.sh

printf '%s\n' "RIAK local CI checks: PASS"
