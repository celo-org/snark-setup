use snark_utils::{beacon_randomness, get_rng, user_system_randomness};

use gumdrop::Options;
use std::process;

mod cli;
use cli::*;

#[macro_use]
extern crate hex_literal;

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
            // Place block hash here (block number #564321)
            let beacon_hash: [u8; 32] =
                hex!("0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620");
            let mut rng = get_rng(&beacon_randomness(beacon_hash));
            contribute(&opt, &mut rng)
        }
        Command::Verify(ref opt) => verify(&opt),
    };

    if let Err(e) = res {
        eprintln!("Failed to execute {:?}: {}", command, e);
    }
}
