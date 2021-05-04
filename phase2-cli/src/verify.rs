use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, SubgroupCheckMode, UseCompression};

use algebra::BW6_761;

use std::io::Write;
use tracing::info;

const PREVIOUS_CHALLENGE_IS_COMPRESSED: UseCompression = UseCompression::No;
const CONTRIBUTION_IS_COMPRESSED: UseCompression = UseCompression::Yes;

pub fn verify(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    check_input_correctness: CheckForCorrectness,
    response_filename: &str,
    response_hash_filename: &str,
    check_output_correctness: CheckForCorrectness,
    subgroup_check_mode: SubgroupCheckMode,
) {
    info!("Verifying phase 2");

    let challenge_contents = std::fs::read(challenge_filename).expect("should have read challenge");
    let challenge_hash = calculate_hash(&challenge_contents);
    std::fs::File::create(challenge_hash_filename)
        .expect("unable to open current accumulator hash file")
        .write_all(&challenge_hash)
        .expect("unable to write current accumulator hash");

    info!("`challenge` file contains decompressed points and has a hash:");
    print_hash(&challenge_hash);

    let parameters_before = MPCParameters::<BW6_761>::read_fast(
        challenge_contents.as_slice(),
        PREVIOUS_CHALLENGE_IS_COMPRESSED,
        check_input_correctness,
        true,
        subgroup_check_mode,
    )
    .expect("should have read parameters");

    let response_contents = std::fs::read(response_filename).expect("should have read response");
    let response_hash = calculate_hash(&response_contents);
    std::fs::File::create(response_hash_filename)
        .expect("unable to open current accumulator hash file")
        .write_all(&response_hash)
        .expect("unable to write current accumulator hash");

    info!("`response` file contains decompressed points and has a hash:");
    print_hash(&response_hash);

    let parameters_after = MPCParameters::<BW6_761>::read_fast(
        response_contents.as_slice(),
        CONTRIBUTION_IS_COMPRESSED,
        check_output_correctness,
        true,
        subgroup_check_mode,
    )
    .expect("should have read parameters");

    parameters_before
        .verify(&parameters_after)
        .expect("should have successfully verified");
    info!(
        "Done!\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    print_hash(&response_hash);
}
