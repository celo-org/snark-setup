#!/bin/bash -e

export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=$1
POWER=18
BATCH=131072
CURVE="bw6"

# rm phase1
RUST_LOG=debug cargo $CARGO_VER build --release --bin prepare_phase2

prepare_phase2="../../target/release/prepare_phase2 --curve-kind $CURVE --batch-size $BATCH --power $POWER --proving-system $PROVING_SYSTEM"

echo "Running prepare phase2..."
export RUST_LOG=debug
$prepare_phase2 --phase2-fname phase1 --response-fname response_beacon

echo "Done with preparing phase2!"