extern crate stark_platinum_prover;
extern crate lambdaworks_math;
extern crate lambdaworks_crypto;
extern crate rand;
extern crate psiri_vole;
extern crate serde_json;
extern crate rayon;

use psiri_vole::fri::{commit_poly, verify_fri_query, query_phase, FriLayer};
use stark_platinum_prover::transcript::StoneProverTranscript;
use stark_platinum_prover::proof::stark::StarkProof;
use stark_platinum_prover::fri::fri_decommit::FriDecommitment;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::{
    fft::cpu::bit_reversing::in_place_bit_reverse_permute, field::traits::IsSubFieldOf,
    fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset,
};
use lambdaworks_math::polynomial::Polynomial;
use lambdaworks_math::field::traits::IsFFTField;
use lambdaworks_crypto::merkle_tree::merkle::{MerkleTree};
use lambdaworks_crypto::merkle_tree::traits::IsMerkleTreeBackend;
use lambdaworks_crypto::merkle_tree::proof::Proof;
use stark_platinum_prover::config::{Commitment, BatchedMerkleTreeBackend, BatchedMerkleTree};
use rand::{random, Rng};
use std::fmt::Debug;
use std::time::Instant;
// use serde_json;
use rayon::current_num_threads;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;
pub type B = BatchedMerkleTreeBackend<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

pub fn sample_usize(min: usize, max: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(min..max)
}


fn main() {
    // Set the number of threads before running parallel operations
    ThreadPoolBuilder::new()
        .num_threads(8)  // Change this number to your preference
        .build_global()
        .unwrap();
    let num_threads = current_num_threads();
    println!("🚀 Rayon is using {} threads", num_threads);
    // Set the polynomial degree
    let log_size: usize = 20;
    let log_blowup_factor: usize = 2;
    let polynomial_degree = 1 << log_size; // Degree = polynomial_degree - 1
    let domain_size = polynomial_degree; // Example domain size (must be >= polynomial_degree)

    // Initialize a random polynomial with `polynomial_degree` coefficients
    let evals: Vec<FE> = (0..polynomial_degree).map(|_| rand_field_element()).collect();
    let poly = Polynomial::new(&evals);

    // println!("Evals:");
    // for eval in evals.iter() {
    //     println!("{:?}", eval);
    // }
    let roots_of_unity = get_powers_of_primitive_root_coset(
        (log_size + log_blowup_factor) as u64,
        1 << (log_size + log_blowup_factor) as usize,
        &FE::one(),
    )
    .unwrap();
    let mut roots_of_unity_inv = roots_of_unity.clone();
    roots_of_unity_inv[1..].reverse();
    let mut reversed_roots_of_unity_inv = roots_of_unity_inv.clone();
    in_place_bit_reverse_permute(&mut reversed_roots_of_unity_inv);

    let start = Instant::now();
    let (last_value, fri_layer_list) = commit_poly(&poly, log_size, log_blowup_factor, log_size, &roots_of_unity, &roots_of_unity_inv); 

    println!("Total time to commit: {:?}", start.elapsed());
}
