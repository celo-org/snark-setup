#!/bin/bash -e

rm -f challenge* response* new_challenge* new_response* new_new_challenge_* processed* initial_ceremony* response_list* combined* seed* chunk*

export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=groth16
POWER=18
BATCH=131072
CHUNK_SIZE=131072
CURVE="bw6"
SEED1=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED1 > seed1
SEED2=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED2 > seed2

function check_hash() {
  test "`xxd -p -c 64 $1.hash`" = "`b2sum $1 | awk '{print $1}'`"
}

cargo $CARGO_VER build --release --bin phase2

phase2_chunked="../../target/release/phase2 --curve-kind $CURVE --chunk-size $CHUNK_SIZE --batch-size $BATCH --contribution-mode full --proving-system $PROVING_SYSTEM"
####### Phase 2

$phase2_chunked new --challenge-fname challenge --challenge-hash-fname challenge.verified.hash --phase1-fname ../../phase1-tests/phase1 --phase1-powers $POWER --num-validators 1 --num-epochs 1

echo "Done!"