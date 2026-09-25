#!/usr/bin/env bash
set -euo pipefail

cargo check --all-targets
cargo test --release --all-targets
python3 simulator/riak_v2.py
python3 simulator/riak_v3.py
python3 simulator/generate_v3_vectors.py

# Fast deterministic screening runs; increase sample counts for a deeper audit.
cargo run --release --example v2_differential 65536
cargo run --release --example v2_full_linear 8192
cargo run --release --example v2_related 256
cargo run --release --example v2_trail_search 4096 10000 8
cargo run --release --example v3_sample -- wildan
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

printf '%s\n' "RIAK local CI checks: PASS"
