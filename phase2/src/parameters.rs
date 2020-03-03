use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use snark_utils::*;
use std::fmt;
use std::io::{self, Read, Write};

use zexe_algebra::{AffineCurve, Field, One, PairingEngine, ProjectiveCurve, Zero};
use zexe_groth16::{KeypairAssembly, Parameters, VerifyingKey};
use zexe_r1cs_core::{ConstraintSynthesizer, ConstraintSystem, Index, SynthesisError, Variable};

use rand::Rng;

use super::keypair::{hash_cs_pubkeys, Keypair, PublicKey};
use super::polynomial::eval;

/// MPC parameters are just like Zexe's `Parameters` except, when serialized,
/// they contain a transcript of contributions at the end, which can be verified.
#[derive(Clone)]
pub struct MPCParameters<E: PairingEngine> {
    pub params: Parameters<E>,
    pub cs_hash: [u8; 64],
    pub contributions: Vec<PublicKey<E>>,
}

impl<E: PairingEngine> fmt::Debug for MPCParameters<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MPCParameters {{ params: {:?}, cs_hash: {:?}, contributions: {:?}}}",
            self.params,
            &self.cs_hash[..],
            self.contributions
        )
    }
}

impl<E: PairingEngine + PartialEq> PartialEq for MPCParameters<E> {
    fn eq(&self, other: &MPCParameters<E>) -> bool {
        self.params == other.params
            && &self.cs_hash[..] == other.cs_hash.as_ref()
            && self.contributions == other.contributions
    }
}

impl<E: PairingEngine> MPCParameters<E> {
    pub fn new_from_buffer<C>(
        circuit: C,
        transcript: (&[u8], UseCompression), // TODO: Replace with a Reader!
        phase2_size: usize,
    ) -> Result<MPCParameters<E>>
    where
        C: ConstraintSynthesizer<E::Fr>,
    {
        let assembly = circuit_to_qap::<E, _>(circuit)?;
        let params = Groth16Params::<E>::read(transcript, phase2_size)?;
        Self::new(assembly, params)
    }

    /// Create new Groth16 parameters (compatible with Zexe) for a
    /// given circuit. The resulting parameters are unsafe to use
    /// until there are contributions (see `contribute()`).
    pub fn new(assembly: KeypairAssembly<E>, params: Groth16Params<E>) -> Result<MPCParameters<E>> {
        // Evaluate the QAP against the coefficients created from phase 1
        let (a_g1, b_g1, b_g2, gamma_abc_g1, l) = eval::<E>(
            // Lagrange coeffs for Tau, read in from Phase 1
            &params.coeffs_g1,
            &params.coeffs_g2,
            &params.alpha_coeffs_g1,
            &params.beta_coeffs_g1,
            // QAP polynomials of the circuit
            &assembly.at,
            &assembly.bt,
            &assembly.ct,
            // Helper
            assembly.num_inputs,
        );

        // Reject unconstrained elements, so that
        // the L query is always fully dense.
        for e in l.iter() {
            if e.is_zero() {
                return Err(SynthesisError::UnconstrainedVariable.into());
            }
        }

        let vk = VerifyingKey {
            alpha_g1: params.alpha_g1,
            beta_g2: params.beta_g2,
            // Gamma_g2 is always 1, since we're implementing
            // BGM17, pg14 https://eprint.iacr.org/2017/1050.pdf
            gamma_g2: E::G2Affine::prime_subgroup_generator(),
            delta_g2: E::G2Affine::prime_subgroup_generator(),
            gamma_abc_g1,
        };
        let params = Parameters {
            vk,
            beta_g1: params.beta_g1,
            delta_g1: E::G1Affine::prime_subgroup_generator(),
            a_query: a_g1,
            b_g1_query: b_g1,
            b_g2_query: b_g2,
            h_query: params.h_g1,
            l_query: l,
        };

        let cs_hash = hash_params(&params)?;
        Ok(MPCParameters {
            params,
            cs_hash,
            contributions: vec![],
        })
    }

    /// Get the underlying Groth16 `Parameters`
    pub fn get_params(&self) -> &Parameters<E> {
        &self.params
    }

    /// Contributes some randomness to the parameters. Only one
    /// contributor needs to be honest for the parameters to be
    /// secure.
    ///
    /// This function returns a "hash" that is bound to the
    /// contribution. Contributors can use this hash to make
    /// sure their contribution is in the final parameters, by
    /// checking to see if it appears in the output of
    /// `MPCParameters::verify`.
    pub fn contribute<R: Rng>(&mut self, rng: &mut R) -> Result<[u8; 64]> {
        // Generate a keypair
        let Keypair {
            public_key,
            private_key,
        } = Keypair::new(self.params.delta_g1, self.cs_hash, &self.contributions, rng);

        // Invert delta and multiply the query's `l` and `h` by it
        let delta_inv = private_key.delta.inverse().expect("nonzero");
        batch_mul(&mut self.params.l_query, &delta_inv)?;
        batch_mul(&mut self.params.h_query, &delta_inv)?;

        // Multiply the `delta_g1` and `delta_g2` elements by the private key's delta
        self.params.delta_g1 = self.params.delta_g1.mul(private_key.delta).into_affine();
        self.params.vk.delta_g2 = self.params.vk.delta_g2.mul(private_key.delta).into_affine();
        // Ensure the private key is no longer used
        drop(private_key);
        self.contributions.push(public_key.clone());

        // Return the pubkey's hash
        Ok(public_key.hash())
    }

    /// Verify the correctness of the parameters, given a circuit
    /// instance. This will return all of the hashes that
    /// contributors obtained when they ran
    /// `MPCParameters::contribute`, for ensuring that contributions
    /// exist in the final parameters.
    pub fn verify(&self, after: &Self) -> Result<Vec<[u8; 64]>> {
        let before = self;

        let pubkey = if let Some(pubkey) = after.contributions.last() {
            pubkey
        } else {
            // if there were no contributions then we should error
            return Err(Phase2Error::NoContributions.into());
        };
        // Current parameters should have consistent delta in G1
        ensure_unchanged(
            pubkey.delta_after,
            after.params.delta_g1,
            InvariantKind::DeltaG1,
        )?;
        // Current parameters should have consistent delta in G2
        check_same_ratio::<E>(
            &(E::G1Affine::prime_subgroup_generator(), pubkey.delta_after),
            &(
                E::G2Affine::prime_subgroup_generator(),
                after.params.vk.delta_g2,
            ),
            "Incosistent G2 Delta",
        )?;

        // None of the previous transformations should change
        ensure_unchanged(
            &before.contributions[..],
            &after.contributions[0..before.contributions.len()],
            InvariantKind::Contributions,
        )?;

        // cs_hash should be the same
        ensure_unchanged(
            &before.cs_hash[..],
            &after.cs_hash[..],
            InvariantKind::CsHash,
        )?;

        // H/L will change, but should have same length
        ensure_same_length(&before.params.h_query, &after.params.h_query)?;
        ensure_same_length(&before.params.l_query, &after.params.l_query)?;

        // A/B_G1/B_G2/Gamma G1/G2 doesn't change at all
        ensure_unchanged(
            before.params.vk.alpha_g1,
            after.params.vk.alpha_g1,
            InvariantKind::AlphaG1,
        )?;
        ensure_unchanged(
            before.params.beta_g1,
            after.params.beta_g1,
            InvariantKind::BetaG1,
        )?;
        ensure_unchanged(
            before.params.vk.beta_g2,
            after.params.vk.beta_g2,
            InvariantKind::BetaG2,
        )?;
        ensure_unchanged(
            before.params.vk.gamma_g2,
            after.params.vk.gamma_g2,
            InvariantKind::GammaG2,
        )?;
        ensure_unchanged_vec(
            &before.params.vk.gamma_abc_g1,
            &after.params.vk.gamma_abc_g1,
            InvariantKind::GammaAbcG1,
        )?;

        // === Query related consistency checks ===

        // H and L queries should be updated with delta^-1
        check_same_ratio::<E>(
            &merge_pairs(&before.params.h_query, &after.params.h_query),
            &(after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
            "H_query ratio check failed",
        )?;

        check_same_ratio::<E>(
            &merge_pairs(&before.params.l_query, &after.params.l_query),
            &(after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
            "L_query ratio check failed",
        )?;

        // generate the transcript from the current contributions and the previous cs_hash
        verify_transcript(before.cs_hash, &after.contributions)
    }

    /// Serialize these parameters. The serialized parameters
    /// can be read by Zexe's Groth16 `Parameters`.
    pub fn write<W: Write>(&self, mut writer: W) -> Result<()> {
        // TODO: This is unimplemented
        self.params.write(&mut writer)?;
        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;
        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        Ok(())
    }

    /// Deserialize these parameters. If `checked` is false,
    /// we won't perform curve validity and group order
    /// checks.
    pub fn read<R: Read>(mut reader: R, checked: bool) -> Result<MPCParameters<E>> {
        let params = Parameters::read(&mut reader, checked)?;

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions_len = reader.read_u32::<BigEndian>()? as usize;

        let mut contributions = vec![];
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut reader)?);
        }

        Ok(MPCParameters {
            params,
            cs_hash,
            contributions,
        })
    }
}

/// This is a cheap helper utility that exists purely
/// because Rust still doesn't have type-level integers
/// and so doesn't implement `PartialEq` for `[T; 64]`
pub fn contains_contribution(contributions: &[[u8; 64]], my_contribution: &[u8; 64]) -> bool {
    for contrib in contributions {
        if &contrib[..] == my_contribution.as_ref() {
            return true;
        }
    }

    false
}

// Helpers for invariant checking
fn ensure_same_length<T, U>(a: &[T], b: &[U]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Phase2Error::InvalidLength.into());
    }
    Ok(())
}

fn ensure_unchanged_vec<T: PartialEq>(
    before: &[T],
    after: &[T],
    kind: InvariantKind,
) -> Result<()> {
    if before.len() != after.len() {
        return Err(Phase2Error::InvalidLength.into());
    }
    for (before, after) in before.iter().zip(after) {
        ensure_unchanged(before, after, kind.clone())?
    }
    Ok(())
}

fn ensure_unchanged<T: PartialEq>(before: T, after: T, kind: InvariantKind) -> Result<()> {
    if before != after {
        return Err(Phase2Error::BrokenInvariant(kind).into());
    }
    Ok(())
}

fn verify_transcript<E: PairingEngine>(
    cs_hash: [u8; 64],
    contributions: &[PublicKey<E>],
) -> Result<Vec<[u8; 64]>> {
    let mut result = vec![];
    let mut old_delta = E::G1Affine::prime_subgroup_generator();
    for (i, pubkey) in contributions.iter().enumerate() {
        let hash = hash_cs_pubkeys(cs_hash, &contributions[0..i], pubkey.s, pubkey.s_delta);
        ensure_unchanged(
            &pubkey.transcript[..],
            &hash.as_ref()[..],
            InvariantKind::Transcript,
        )?;

        // generate the G2 point from the hash
        let r = hash_to_g2::<E>(hash.as_ref()).into_affine();

        // Check the signature of knowledge
        check_same_ratio::<E>(
            &(pubkey.s, pubkey.s_delta),
            &(r, pubkey.r_delta),
            "Incorrect signature of knowledge",
        )?;

        // Check the change with the previous G1 Delta is consistent
        check_same_ratio::<E>(
            &(old_delta, pubkey.delta_after),
            &(r, pubkey.r_delta),
            "Incosistent G1 Delta",
        )?;
        old_delta = pubkey.delta_after;

        result.push(pubkey.hash());
    }

    Ok(result)
}

#[allow(unused)]
fn hash_params<E: PairingEngine>(params: &Parameters<E>) -> Result<[u8; 64]> {
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    // TODO: Re-enable this
    // params.write(&mut sink)?;
    let h = sink.into_hash();
    let mut cs_hash = [0; 64];
    cs_hash.copy_from_slice(h.as_ref());
    Ok(cs_hash)
}

/// Converts an R1CS circuit to QAP form
pub fn circuit_to_qap<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>>(
    circuit: C,
) -> Result<KeypairAssembly<E>> {
    let mut assembly = KeypairAssembly::<E> {
        num_inputs: 0,
        num_aux: 0,
        num_constraints: 0,
        at: vec![],
        bt: vec![],
        ct: vec![],
    };

    // Allocate the "one" input variable
    assembly.alloc_input(|| "", || Ok(E::Fr::one()))?;
    // Synthesize the circuit.
    circuit.generate_constraints(&mut assembly)?;
    // Input constraints to ensure full density of IC query
    // x * 0 = 0
    for i in 0..assembly.num_inputs {
        assembly.enforce(
            || "",
            |lc| lc + Variable::new_unchecked(Index::Input(i)),
            |lc| lc,
            |lc| lc,
        );
    }

    Ok(assembly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use powersoftau::{parameters::CeremonyParams, BatchedAccumulator};
    use rand::thread_rng;
    use snark_utils::{Groth16Params, UseCompression};
    use test_helpers::{setup_verify, TestCircuit};
    use zexe_algebra::Bls12_381;

    #[test]
    #[ignore]
    // temporarily ignore until read/write for Parameters is merged: https://github.com/scipr-lab/zexe/pull/109
    fn serialize_ceremony() {
        serialize_ceremony_curve::<Bls12_381>()
    }

    fn serialize_ceremony_curve<E: PairingEngine + PartialEq>() {
        let mpc = generate_ceremony::<E>();

        let mut writer = vec![];
        mpc.write(&mut writer).unwrap();
        let mut reader = vec![0; writer.len()];
        reader.copy_from_slice(&writer);
        let deserialized = MPCParameters::<E>::read(&reader[..], false).unwrap();
        assert_eq!(deserialized, mpc)
    }

    #[test]
    fn verify_with_self_fails() {
        verify_with_self_fails_curve::<Bls12_381>()
    }

    // if there has been no contribution
    // then checking with itself should fail
    fn verify_with_self_fails_curve<E: PairingEngine>() {
        let mpc = generate_ceremony::<E>();
        let err = mpc.verify(&mpc);
        // we handle the error like this because [u8; 64] does not implement
        // debug, meaning we cannot call `assert` on it
        if let Err(e) = err {
            assert_eq!(
                e.to_string(),
                "Phase 2 Error: There were no contributions found"
            );
        } else {
            panic!("Verifying with self must fail")
        }
    }
    #[test]
    fn verify_contribution() {
        verify_curve::<Bls12_381>()
    }

    // contributing once and comparing with the previous step passes
    fn verify_curve<E: PairingEngine>() {
        let rng = &mut thread_rng();
        // original
        let mpc = generate_ceremony::<E>();

        // somebody contributes
        let mut contribution1 = mpc.clone();
        contribution1.contribute(rng).unwrap();

        // try to verify it against the previous step
        mpc.verify(&contribution1).unwrap();

        // somebody else contributes
        let mut contribution2 = contribution1.clone();
        contribution2.contribute(rng).unwrap();

        // verification passes against the previous step
        contribution1.verify(&contribution2).unwrap();

        // verification passes against the initial params
        mpc.verify(&contribution2).unwrap();
    }

    // helper which generates the initial phase 2 params
    // for the TestCircuit
    fn generate_ceremony<E: PairingEngine>() -> MPCParameters<E> {
        let powers = 3;
        let batch = 4;
        let phase2_size = 7;
        let params = CeremonyParams::<E>::new(powers, batch);
        let accumulator = {
            let compressed = UseCompression::No;
            let (_, output, _, _) = setup_verify(compressed, compressed, &params);
            BatchedAccumulator::deserialize(&output, compressed, &params).unwrap()
        };

        let groth_params = Groth16Params::<E>::new(
            phase2_size,
            accumulator.tau_powers_g1,
            accumulator.tau_powers_g2,
            accumulator.alpha_tau_powers_g1,
            accumulator.beta_tau_powers_g1,
            accumulator.beta_g2,
        );

        // this circuit requires 7 constraints, so a ceremony with size 8 is sufficient
        let c = TestCircuit::<E>(None);
        let assembly = circuit_to_qap::<E, _>(c).unwrap();

        MPCParameters::new(assembly, groth_params).unwrap()
    }
}
