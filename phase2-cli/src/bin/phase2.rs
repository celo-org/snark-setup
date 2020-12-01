use setup_utils::converters::CurveKind;

use algebra::{Bls12_377, PairingEngine as Engine, BW6_761};

use gumdrop::Options;
use phase2_cli::{new_challenge, Command, Phase2Opts};
use std::{process, time::Instant};
use tracing::{error, info};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

fn execute_cmd<E: Engine>(opts: Phase2Opts) {
    let command = opts.clone().command.unwrap_or_else(|| {
        error!("No command was provided.");
        error!("{}", Phase2Opts::usage());
        process::exit(2)
    });

    let now = Instant::now();

    match command {
        Command::New(opt) => {
            new_challenge(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                opts.chunk_size,
                &opt.phase1_fname,
                opt.phase1_powers,
                opt.num_validators,
                opt.num_epochs,
            );
        }
    };

    let new_now = Instant::now();
    info!("Executing {:?} took: {:?}", opts, new_now.duration_since(now));
}

fn main() {
    Subscriber::builder()
        .with_target(false)
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: Phase2Opts = Phase2Opts::parse_args_default_or_exit();

    match opts.curve_kind {
        CurveKind::Bls12_377 => execute_cmd::<Bls12_377>(opts),
        CurveKind::BW6 => execute_cmd::<BW6_761>(opts),
    };
}
