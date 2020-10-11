#!/bin/bash -e

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined* seed*

PROVING_SYSTEM=$1
POWER=10
BATCH=64
CURVE="bw6"
SEED=`tr -dc 'A-F0-9' < /dev/urandom | head -c32`
echo $SEED > seed1

function check_hash() {
  test "`xxd -p -c 64 $1.hash`" = "`b2sum $1 | awk '{print $1}'`"
}

phase1="cargo run --release --bin phase1 -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --seed seed1 --proving-system $PROVING_SYSTEM"

####### Phase 1

$phase1 new --challenge-fname challenge
yes | $phase1 contribute --challenge-fname challenge --current-accumulator-hash-fname challenge.hash --response-fname response --contribution-hash-fname response.hash
check_hash challenge
check_hash response
$phase1 verify-and-transform-pok-and-correctness --challenge-fname challenge --response-fname response --new-challenge-fname new_challenge
$phase1 beacon --challenge-fname new_challenge --current-accumulator-hash-fname new_challenge.hash --response-fname new_response --contribution-hash-fname new_response.hash --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$phase1 verify-and-transform-pok-and-correctness --challenge-fname new_challenge --response-fname new_response --new-challenge-fname new_challenge_2
$phase1 verify-and-transform-ratios --response-fname new_challenge_2
