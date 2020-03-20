#!/bin/bash

rm -f challenge* response* new_challenge* processed*

POWER=10
BATCH=256
NUM_CONSTRAINTS=1048576
NUM_VALIDATORS=5
NUM_EPOCHS=2
CURVE="sw6"

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $POWER"
phase2="cargo run --release --bin prepare_phase2 -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --phase2-size $POWER"
snark="cargo run --release --bin bls-snark-setup --"

# generate powers of tau (run it through a couple contribs)
$powersoftau new --challenge-fname challenge
yes | $powersoftau contribute --challenge-fname challenge --response-fname response
$powersoftau verify-and-transform --challenge-fname challenge --response-fname response --new-challenge-fname new_challenge
rm challenge response && mv new_challenge challenge

yes | $powersoftau contribute --challenge-fname challenge --response-fname response
$powersoftau verify-and-transform --challenge-fname challenge --response-fname response --new-challenge-fname new_challenge
rm challenge response && mv new_challenge challenge

yes | $powersoftau contribute --challenge-fname challenge --response-fname response

# take the last contrib and prepare it for phase 2
$phase2 --response-fname response --phase2-fname processed

# read the prepared params and create the initial phase2 MPC
rm challenge
$snark new --phase1 processed --output challenge --num-epochs $NUM_EPOCHS --num-validators $NUM_VALIDATORS --num-constraints $NUM_CONSTRAINTS

# contribute a few times to the mpc
$snark contribute --input challenge --output contribution

$snark contribute --input contribution --output contribution1
rm contribution # no longer needed

$snark contribute --input contribution1 --output contribution2
rm contribution1 # no longer needed

$snark contribute --input contribution --output contribution3

# verify the last mpc against the initial mpc
$snark verify --before challenge --after contribution3

# done! since `verify` passed, you can be sure that this will work 
# as shown in the `mpc.rs` example