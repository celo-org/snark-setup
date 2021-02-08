use epoch_snark::{prove, trusted_setup, verify, BLSCurve, BWCurve, Parameters};
use phase2::parameters::MPCParameters;
use std::env;

#[path = "../tests/fixtures.rs"]
mod fixtures;
use fixtures::generate_test_data;

use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

use bench_utils::{end_timer, start_timer};
use setup_utils::{CheckForCorrectness, SubgroupCheckMode, UseCompression};

fn main() {
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let rng = &mut rand::thread_rng();
    let mut args = env::args();
    args.next().unwrap(); // discard the program name
    let num_validators = args.next().expect("num validators was expected").parse().expect("NaN");
    let num_epochs = args.next().expect("num epochs was expected").parse().expect("NaN");
    let hashes_in_bls12_377: bool = args
        .next()
        .expect("expected flag for generating or not constraints inside BLS12_377")
        .parse()
        .expect("not a bool");
    let use_params_file: bool = args
        .next()
        .expect("expected flag for whether to load setup params from file")
        .parse()
        .expect("not a bool");
    let faults = (num_validators - 1) / 3;

    // Trusted setup
    let time = start_timer!(|| "Trusted setup");
    let params = match use_params_file {
        false => trusted_setup(num_validators, num_epochs, faults, rng, hashes_in_bls12_377).unwrap(),
        true => {
            if hashes_in_bls12_377 {
                panic!("can't both load params from file and use hashes in BLS12-377");
            }
            let setup_contents = std::fs::read("params").unwrap();

            Parameters::<BWCurve, BLSCurve> {
                epochs: MPCParameters::read_groth16_fast(
                    &mut std::io::Cursor::new(setup_contents),
                    UseCompression::No,
                    CheckForCorrectness::No,
                    false,
                    SubgroupCheckMode::Auto,
                )
                .unwrap(),
                hash_to_bits: None,
            }
        }
    };
    end_timer!(time);

    // Create the state to be proven (first - last and in between)
    // Note: This is all data which should be fetched via the Celo blockchain
    let (first_epoch, transitions, last_epoch) = generate_test_data(num_validators, faults, num_epochs);

    // Prover generates the proof given the params
    let time = start_timer!(|| "Generate proof");
    let proof = prove(&params, num_validators as u32, &first_epoch, &transitions, num_epochs).unwrap();
    end_timer!(time);

    // Verifier checks the proof
    let time = start_timer!(|| "Verify proof");
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    end_timer!(time);
    assert!(res.is_ok());
}
