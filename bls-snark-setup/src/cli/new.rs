use gumdrop::Options;

use bls_snark::gadgets::ValidatorSetUpdate;
use zexe_algebra::SW6;

use phase2::parameters::{circuit_to_qap, MPCParameters};
use snark_utils::{Groth16Params, Result, UseCompression};

use std::fs::OpenOptions;

#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,
    #[options(help = "the path to the phase1 parameters", default = "phase1")]
    pub phase1: String,
    #[options(help = "the challenge file name to be created", default = "challenge")]
    pub output: String,
    #[options(
        help = "the number of epochs the snark will prove",
        default = "180" // 6 months
    )]
    pub num_epochs: usize,
    #[options(
        help = "the number of validators the snark will support",
        default = "100"
    )]
    pub num_validators: usize,

    #[options(help = "the number of constraints to be taken from phase 1")]
    pub num_constraints: usize,
}

const COMPRESSION: UseCompression = UseCompression::Yes;

pub fn new(opt: &NewOpts) -> Result<()> {
    let mut phase1_transcript = OpenOptions::new()
        .read(true)
        .open(&opt.phase1)
        .expect("could not read phase 1 transcript file");
    let output = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(&opt.output)
        .expect("could not open file for writing the MPC parameters ");

    let maximum_non_signers = (opt.num_validators - 1) / 3;

    // Read the data from the file
    let phase1 =
        Groth16Params::<SW6>::read(&mut phase1_transcript, COMPRESSION, opt.num_constraints)?;

    // Create an empty circuit
    let valset = ValidatorSetUpdate::empty(
        opt.num_validators,
        opt.num_epochs,
        maximum_non_signers,
        None, // The hashes are done over SW6 so no helper is provided for the setup
    );
    // Convert it to a QAP
    let keypair = circuit_to_qap(valset)?;

    // Generate the initial transcript
    let mpc = MPCParameters::new(keypair, phase1)?;
    mpc.write(output)?;

    Ok(())
}
