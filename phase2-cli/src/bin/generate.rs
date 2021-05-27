/*use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bls12_377::Fq;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, Field, Matrix, SynthesisMode, Variable};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use epoch_snark::ValidatorSetUpdate;
use std::env;
use std::fs::File;

#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Matrices<F: Field> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,
    /// The number of non_zero entries in the A matrix.
    pub a_num_non_zero: usize,
    /// The number of non_zero entries in the B matrix.
    pub b_num_non_zero: usize,
    /// The number of non_zero entries in the C matrix.
    pub c_num_non_zero: usize,

    /// The A constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub a: Matrix<F>,
    /// The B constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub b: Matrix<F>,
    /// The C constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub c: Matrix<F>,
}

fn main() -> Result<()> {
    let mut args = env::args();
    args.next().unwrap(); // discard the program name
    let num_validators = args.next().expect("num validators was expected").parse().expect("NaN");
    let num_epochs = args.next().expect("num epochs was expected").parse().expect("NaN");
    let faults = (num_validators - 1) / 3;

    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    let circuit = ValidatorSetUpdate::<Bls12_377>::empty(num_validators, num_epochs, faults, None);
    circuit.generate_constraints(cs.clone()).unwrap();
    //for i in 0..cs.num_instance_variables() {
    //    cs.enforce_constraint(lc!() + Variable::Instance(i), lc!(), lc!())?;
    // }
    cs.inline_all_lcs();

    let m = cs.to_matrices().unwrap();
    let m_for_ser = Matrices {
        a: m.a,
        b: m.b,
        c: m.c,
        a_num_non_zero: m.a_num_non_zero,
        b_num_non_zero: m.b_num_non_zero,
        c_num_non_zero: m.c_num_non_zero,
        num_instance_variables: m.num_instance_variables,
        num_witness_variables: m.num_witness_variables,
        num_constraints: m.num_constraints,
    };

    let mut bytes = vec![];
    m_for_ser.serialize(&mut bytes)?;

    let mut file = File::create("test.contraints")?;
    file.write_all(&bytes)?;

    println!(
        "Number of constraints for {} epochs ({} validators, {} faults, hashes in BW6_761): {}, serialized size: {}",
        num_epochs,
        num_validators,
        faults,
        cs.num_constraints(),
        bytes.len(),
    );

    let mut file = File::open("test.contraints")?;
    // read the same file back into a Vec of bytes
    let mut buffer = Vec::<u8>::new();
    file.read_to_end(&mut buffer)?;

    let m = Matrices::<Fq>::deserialize(&*buffer)?;

    let (at, bt, ct) = {
        let matrices = cs.to_matrices().unwrap();
        (matrices.a, matrices.b, matrices.c)
    };
    println!("{}, {}, {}", at == m.a, bt == m.b, ct == m.c);
    println!(
        "Number of constraints for {} epochs ({} validators, {} faults, hashes in BW6_761): {}, serialized size: {}",
        num_epochs,
        num_validators,
        faults,
        m.num_constraints,
        buffer.len(),
    );

    Ok(())
}*/

fn main() {
    unimplemented!(); 
}
