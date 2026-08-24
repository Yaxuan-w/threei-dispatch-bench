#!/usr/bin/env bash
# Reproduce the numbers in README.md.
set -euo pipefail
cargo build --release
./target/release/bench --trials 9 --csv results.csv "$@"
echo
echo "--- same thing with a real host syscall at the bottom ---"
./target/release/bench --trials 7 --leaf syscall --grates 1 --threads 1 --csv results-syscall-leaf.csv
