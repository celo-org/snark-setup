use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use powersoftau::utils::{batch_exp, dense_multiexp, generate_powers_of_tau};
use rand::Rng;
use std::ops::MulAssign;
use zexe_algebra::{
    curves::bls12_377::{Bls12_377, G1Affine},
    AffineCurve, Field, PairingEngine, PrimeField, UniformRand, Zero,
};
mod utils;
use utils::random_point_vec;

// This was the previous implementation using chunks, we keep it here to compare performance
// against the Rayon implementation
pub fn generate_powers_of_tau_crossbeam<E: PairingEngine>(
    tau: &E::Fr,
    start: usize,
    size: usize,
) -> Vec<E::Fr> {
    // Construct the powers of tau
    let mut taupowers = vec![E::Fr::zero(); size];
    let chunk_size = size / num_cpus::get();

    // Construct exponents in parallel chunks
    crossbeam::scope(|scope| {
        for (i, taupowers) in taupowers.chunks_mut(chunk_size).enumerate() {
            scope.spawn(move || {
                let mut acc = tau.pow(&[(start + i * chunk_size) as u64]);

                for t in taupowers {
                    *t = acc;
                    acc.mul_assign(&tau);
                }
            });
        }
    });
    taupowers
}

// Benchmark showing that the Rayon generator is faster
fn powersoftau_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let start = 0;
    let end = 50;
    let point = <Bls12_377 as PairingEngine>::Fr::rand(&mut rng);

    let mut group = c.benchmark_group("PowersOfTau");
    group.bench_function("rayon", |b| {
        b.iter(|| generate_powers_of_tau::<Bls12_377>(&point, start, end))
    });
    group.bench_function("crossbeam", |b| {
        b.iter(|| generate_powers_of_tau_crossbeam::<Bls12_377>(&point, start, end))
    });
    group.finish();
}

// Benchmark for finding the optimal batch size for batch_exp
fn batchexp_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Exponentiation");
    group.sample_size(10);
    let mut rng = rand::thread_rng();
    let tau = <Bls12_377 as PairingEngine>::Fr::rand(&mut rng);

    for len in (5..12).map(|i| 2u32.pow(i)) {
        group.throughput(Throughput::Elements(len as u64));
        // generate a vector of bases and exponents
        let mut elements: Vec<G1Affine> = random_point_vec(len as usize, &mut rng);
        let powers = generate_powers_of_tau::<Bls12_377>(&tau, 0, len as usize);

        group.bench_with_input("batch_exp", &len, |b, _len| {
            b.iter(|| batch_exp(&mut elements, &powers, None).unwrap())
        });
    }
}

// Benchmark for finding the optimal batch size for power_pairs
fn multiexp_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Multiexp");
    group.sample_size(10);
    let mut rng = rand::thread_rng();
    for len in (5..12).map(|i| 2u32.pow(i)) {
        group.throughput(Throughput::Elements(len as u64));
        let v1: Vec<G1Affine> = random_point_vec(len as usize, &mut rng);
        let randomness = randomness(&v1, &mut rng);

        group.bench_with_input("dense", &len, |b, _len| {
            b.iter(|| dense_multiexp(&v1, &randomness))
        });
    }
}

fn randomness<G: AffineCurve>(
    v: &[G],
    rng: &mut impl Rng,
) -> Vec<<G::ScalarField as PrimeField>::BigInt> {
    (0..v.len())
        .map(|_| G::ScalarField::rand(rng).into_repr())
        .collect()
}

criterion_group!(
    benches,
    powersoftau_benchmark,
    batchexp_benchmark,
    multiexp_benchmark
);
criterion_main!(benches);
