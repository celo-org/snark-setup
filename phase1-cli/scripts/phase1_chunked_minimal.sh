#!/bin/bash -e

rm -f challenge* response* new_challenge* new_response* new_new_challenge_* processed* initial_ceremony* response_list* combined* seed* chunk* phase1

export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=$1
POWER=18
BATCH=131072
CHUNK_SIZE=131072
if [ "$PROVING_SYSTEM" == "groth16" ]; then
  MAX_CHUNK_INDEX=$((4-1)) # we have 4 chunks, since we have a total of 2^11-1 powers
else
  MAX_CHUNK_INDEX=$((2-1)) # we have 2 chunks, since we have a total of 2^11-1 powers
fi
CURVE="bw6"
SEED1=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED1 > seed1

cargo $CARGO_VER build --release --bin phase1

phase1_1="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed1 --proving-system $PROVING_SYSTEM"
phase1_full="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --proving-system $PROVING_SYSTEM"
phase1_combine="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --proving-system $PROVING_SYSTEM"
####### Phase 1

for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  echo "Contributing and verifying chunk $i..."
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.verified.hash
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.hash --response-fname response_$i --response-hash-fname response_$i.hash
  rm challenge_$i # no longer needed
  echo response_$i >> response_list
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  echo "Contributing and verifying chunk $i..."
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.verified.hash
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.hash --response-fname response_$i --response-hash-fname response_$i.hash
  rm challenge_$i # no longer needed
  echo response_$i >> response_list
done

echo "Aggregating..."
$phase1_combine combine --response-list-fname response_list --combined-fname combined

echo "Apply beacon..."
$phase1_full beacon --challenge-fname combined --response-fname response_beacon --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620

echo "Done with phase 1!"