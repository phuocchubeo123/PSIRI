use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use lambdaworks_math::traits::{ByteConversion, AsBytes};
use rand::random;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use stark_platinum_prover::fri::Polynomial;
use rayon::prelude::*;
use rayon::{current_num_threads};
use sha3::{Digest, Keccak256};
use std::time::Instant;
use std::thread;
use std::sync::{Arc, Mutex};



pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

pub fn parallel_fft(coefs: &[FE], roots_of_unity: &[FE], log_size: usize, log_blowup_factor: usize) -> Vec<FE> {
    let size = 1 << (log_size + log_blowup_factor);
    let mut res = vec![FE::zero(); size];
    res[..coefs.len()].copy_from_slice(coefs);
    in_place_bit_reverse_permute(&mut res);

    let mut stride = 1;
    let mut p: usize = log_size + log_blowup_factor - 1;
    let mask = size - 1;

    while stride < size {
        let num_threads = current_num_threads();
        let chunk_size = size / num_threads;

        if 2*stride > chunk_size {
            // let start = Instant::now();

            let small_chunk_size = stride / num_threads;
            for start in (0..size).step_by(2*stride) {
                let (left, right) = res[start..start+2*stride].split_at_mut(stride);
                left.par_chunks_mut(small_chunk_size)
                    .zip(right.par_chunks_mut(small_chunk_size))
                    .enumerate()
                    .for_each(|(i, (left_chunk, right_chunk))| {
                        for j in 0..small_chunk_size {
                            let zp = roots_of_unity[((i*small_chunk_size+j) << p) & mask];
                            let a = left_chunk[j];
                            let b = right_chunk[j];
                            left_chunk[j] = a + zp * b;
                            right_chunk[j] = a - zp * b;
                        }
                    });
            }
            // println!("Time for case 1: {:?}", start.elapsed());

        } else {
            // let start = Instant::now();
            res.par_chunks_mut(chunk_size)
                .enumerate()
                .for_each(|(i, chunk)| {
                    chunk.par_chunks_mut(2*stride).enumerate().for_each(|(i, small_chunk)| {
                        for j in 0..stride {
                            let zp = roots_of_unity[(j << p) & mask];
                            let a = small_chunk[j];
                            let b = small_chunk[j + stride];
                            small_chunk[j] = a + zp * b;
                            small_chunk[j + stride] = a - zp * b;
                        }
                    });
                });
            // println!("Time for case 2: {:?}", start.elapsed());
        }

        stride *= 2;
        p -= 1;
    }

    res
}

pub fn hash_leaves(unhashed_leaves: &[[FE; 2]]) -> Vec<[u8; 32]> {
    let num_threads = current_num_threads();
    let chunk_size = unhashed_leaves.len() / (num_threads);
    let mut hashed_leaves = vec![[0u8; 32]; unhashed_leaves.len()];
    if unhashed_leaves.len() > 2*num_threads {
        let start = Instant::now();

        hashed_leaves.chunks_mut(chunk_size).zip(unhashed_leaves.chunks_exact(chunk_size)).par_bridge().for_each(|(hashed_chunk, unhashed_chunk)| {
            // let start = Instant::now();
            // println!("Using thread {:?}", thread::current());   
            hashed_chunk.iter_mut().zip(unhashed_chunk.iter()).enumerate().for_each(|(i, (hashed, unhashed))| {
                // if i <= 2 {
                //     println!("Using thread {:?} for leaf {}", thread::current(), i);
                // }
                let mut hasher = Keccak256::new();
                hasher.update(unhashed[0].as_bytes());
                hasher.update(unhashed[1].as_bytes());
                let result = hasher.finalize();
                hashed.copy_from_slice(&result);
            });
            // println!("Time when using thread {:?} is {:?}", thread::current(), start.elapsed());
        });


        println!("Time for hashing leaves {:?}", start.elapsed());
    } else {
        unhashed_leaves.par_iter().zip(hashed_leaves.par_iter_mut()).for_each(|(unhashed, hashed)| {
            let mut hasher = Keccak256::new();
            hasher.update(unhashed[0].as_bytes());
            hasher.update(unhashed[1].as_bytes());
            let result = hasher.finalize();
            hashed.copy_from_slice(&result);
        });
    }

    hashed_leaves
}

pub fn sibling_index(node_index: usize) -> usize {
    if node_index % 2 == 0 {
        node_index - 1
    } else {
        node_index + 1
    }
}

pub fn parent_index(node_index: usize) -> usize {
    if node_index % 2 == 0 {
        (node_index - 1) / 2
    } else {
        node_index / 2
    }
}