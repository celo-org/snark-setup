use phase1::{
    helpers::{curve_from_str, proving_system_from_str, CurveKind},
    ContributionMode,
    Phase1,
    Phase1Parameters,
    ProvingSystem,
};
use setup_utils::{
    calculate_hash,
    derive_rng_from_seed,
    get_rng,
    user_system_randomness,
    CheckForCorrectness,
    UseCompression,
};

use zexe_algebra::{Bls12_377, PairingEngine, BW6_761};

use rand::Rng;
use wasm_bindgen::prelude::*;

pub(crate) const COMPRESSED_INPUT: UseCompression = UseCompression::No;
pub(crate) const COMPRESSED_OUTPUT: UseCompression = UseCompression::Yes;
pub(crate) const CHECK_INPUT_CORRECTNESS: CheckForCorrectness = CheckForCorrectness::No;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[derive(Serialize)]
pub struct ContributionResponse {
    current_accumulator_hash: Vec<u8>,
    pub response: Vec<u8>,
    contribution_hash: Vec<u8>,
}

#[wasm_bindgen]
pub struct Phase1WASM {}

#[wasm_bindgen]
impl Phase1WASM {
    #[wasm_bindgen]
    pub fn contribute_full(
        curve_kind: &str,
        proving_system: &str,
        batch_size: usize,
        power: usize,
        challenge: &[u8],
    ) -> Result<JsValue, JsValue> {
        let rng = get_rng(&user_system_randomness());
        let proving_system = proving_system_from_str(proving_system).expect("invalid proving system");
        let res = match curve_from_str(curve_kind).expect("invalid curve_kind") {
            CurveKind::Bls12_377 => contribute_challenge(
                &challenge,
                &get_parameters_full::<Bls12_377>(proving_system, batch_size, power),
                rng,
            ),
            CurveKind::BW6 => contribute_challenge(
                &challenge,
                &get_parameters_full::<BW6_761>(proving_system, batch_size, power),
                rng,
            ),
        };
        return Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap());
    }

    #[wasm_bindgen]
    pub fn contribute_chunked(
        curve_kind: &str,
        proving_system: &str,
        batch_size: usize,
        power: usize,
        chunk_index: usize,
        chunk_size: usize,
        seed: &[u8],
        challenge: &[u8],
    ) -> Result<JsValue, JsValue> {
        let rng = derive_rng_from_seed(seed);
        let proving_system = proving_system_from_str(proving_system).expect("invalid proving system");
        let res = match curve_from_str(curve_kind).expect("invalid curve_kind") {
            CurveKind::Bls12_377 => contribute_challenge(
                &challenge,
                &get_parameters_chunked::<Bls12_377>(proving_system, batch_size, power, chunk_index, chunk_size),
                rng,
            ),
            CurveKind::BW6 => contribute_challenge(
                &challenge,
                &get_parameters_chunked::<BW6_761>(proving_system, batch_size, power, chunk_index, chunk_size),
                rng,
            ),
        };
        return Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap());
    }
}

pub fn get_parameters_full<E: PairingEngine>(
    proving_system: ProvingSystem,
    power: usize,
    batch_size: usize,
) -> Phase1Parameters<E> {
    Phase1Parameters::<E>::new_full(proving_system, power, batch_size)
}

pub fn get_parameters_chunked<E: PairingEngine>(
    proving_system: ProvingSystem,
    power: usize,
    batch_size: usize,
    chunk_index: usize,
    chunk_size: usize,
) -> Phase1Parameters<E> {
    Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        chunk_index,
        chunk_size,
        proving_system,
        power,
        batch_size,
    )
}

pub fn contribute_challenge<E: PairingEngine + Sync>(
    challenge: &[u8],
    parameters: &Phase1Parameters<E>,
    mut rng: impl Rng,
) -> Result<ContributionResponse, String> {
    let expected_challenge_length = match COMPRESSED_INPUT {
        UseCompression::Yes => parameters.contribution_size,
        UseCompression::No => parameters.accumulator_size,
    };

    if challenge.len() != expected_challenge_length {
        return Err(format!(
            "The size of challenge file should be {}, but it's {}, so something isn't right.",
            expected_challenge_length,
            challenge.len()
        ));
    }

    let required_output_length = match COMPRESSED_OUTPUT {
        UseCompression::Yes => parameters.contribution_size,
        UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
    };

    let mut response: Vec<u8> = vec![];
    let current_accumulator_hash = calculate_hash(&challenge);

    for i in 0..required_output_length {
        response.push(current_accumulator_hash[i % current_accumulator_hash.len()]);
    }

    // Construct our keypair using the RNG we created above
    let (public_key, private_key): (phase1::PublicKey<E>, phase1::PrivateKey<E>) =
        match Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref()) {
            Ok(pair) => pair,
            Err(_) => return Err("could not generate keypair".to_string()),
        };

    // This computes a transformation and writes it
    match Phase1::computation(
        &challenge,
        &mut response,
        COMPRESSED_INPUT,
        COMPRESSED_OUTPUT,
        CHECK_INPUT_CORRECTNESS,
        &private_key,
        &parameters,
    ) {
        Ok(_) => match public_key.write(&mut response, COMPRESSED_OUTPUT, &parameters) {
            Ok(_) => {
                let contribution_hash = calculate_hash(&response);

                return Ok(ContributionResponse {
                    current_accumulator_hash: current_accumulator_hash.as_slice().iter().cloned().collect(),
                    response,
                    contribution_hash: contribution_hash.as_slice().iter().cloned().collect(),
                });
            }
            Err(_) => {
                return Err("unable to write public key".to_string());
            }
        },
        Err(_) => {
            return Err("must contribute with the key".to_string());
        }
    }
}
