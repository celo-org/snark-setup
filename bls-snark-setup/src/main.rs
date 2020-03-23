use snark_utils::{beacon_randomness, from_slice, get_rng, user_system_randomness};

use gumdrop::Options;
use std::process;

mod cli;
use cli::*;

fn main() {
    let opts = SNARKOpts::parse_args_default_or_exit();

    let command = opts.command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", SNARKOpts::usage());
        process::exit(2)
    });

    let res = match command {
        Command::New(ref opt) => new(&opt),
        Command::Contribute(ref opt) => {
            // contribute to the randomness
            let mut rng = get_rng(&user_system_randomness());
            contribute(&opt, &mut rng)
        }
        Command::Beacon(ref opt) => {
            // use the beacon's randomness
            let beacon_hash =
                hex::decode(&opt.beacon_hash).expect("could not hex decode beacon hash");
            let mut rng = get_rng(&beacon_randomness(from_slice(&beacon_hash)));
            contribute(&opt, &mut rng)
        }
        Command::Verify(ref opt) => verify(&opt),
    };

    if let Err(e) = res {
        eprintln!("Failed to execute {:?}: {}", command, e);
    }
}
