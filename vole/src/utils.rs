use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use lambdaworks_math::traits::{ByteConversion, AsBytes};
use rand::random;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use stark_platinum_prover::fri::Polynomial;
use rayon::prelude::*;
use rayon::{current_num_threads, scope};
use sha3::{Digest, Keccak256};
use std::time::Instant;
use std::thread;
use std::sync::{Arc, Mutex};
extern crate libc;

fn get_current_cpu() -> i32 {
    unsafe {
        libc::sched_getcpu() // Returns the CPU core number
    }
}



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

    let num_threads = current_num_threads();
    let chunk_size = size / num_threads;


    let new_left: Vec<Arc<Mutex<Vec<FE>>>> = (0..num_threads)
        .map(|_| Arc::new(Mutex::new(Vec::new())))
        .collect(); 
    let new_right: Vec<Arc<Mutex<Vec<FE>>>> = (0..num_threads)
        .map(|_| Arc::new(Mutex::new(Vec::new())))
        .collect();


    while stride < size {
        if 2*stride > num_threads {
            let small_chunk_size = stride / num_threads;
            let remainder = stride % num_threads;
            for start in (0..size).step_by(2*stride) {
                let (left, right) = res[start..start+2*stride].split_at_mut(stride);
                let mut left1 = left.to_vec();
                let mut right1 = right.to_vec();

                (0..num_threads).into_par_iter()
                    .for_each(|i| {
                        let start_idx = i * small_chunk_size;
                        let mut end_idx = 0;
                        if i == num_threads - 1 {
                            end_idx = stride;
                        } else {
                            end_idx = start_idx + small_chunk_size;
                        }

                        let mut left_lock = new_left[i].lock().unwrap();
                        let mut right_lock = new_right[i].lock().unwrap();

                        *left_lock = Vec::with_capacity(end_idx - start_idx);
                        *right_lock = Vec::with_capacity(end_idx - start_idx);

                        for j in 0..(end_idx - start_idx) {
                            let zp = roots_of_unity[((start_idx + j) << p) & mask];
                            let a = left[start_idx + j];
                            let b = right[start_idx + j];
                            left_lock.push(a + zp * b);
                            right_lock.push(a - zp * b);
                        }
                    });
                
                (0..num_threads).into_iter()
                    .for_each(|i| {
                        let start_idx = i * small_chunk_size;
                        let mut end_idx = 0;
                        if i == num_threads - 1 {
                            end_idx = stride;
                        } else {
                            end_idx = start_idx + small_chunk_size;
                        }
                        left[start_idx..end_idx].copy_from_slice(&new_left[i].lock().unwrap());
                        right[start_idx..end_idx].copy_from_slice(&new_right[i].lock().unwrap());
                    });

                left1.par_chunks_mut(small_chunk_size)
                    .zip(right1.par_chunks_mut(small_chunk_size))
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

                println!("Are they equal? {}", left == left1 && right == right1);
            }

        } else {
            // let start = Instant::now();
            let new_chunk_size = chunk_size / (2*stride) * 2*stride;
            (0..(size/new_chunk_size)).into_par_iter()
                .for_each(|i| {
                    let start_idx = i * new_chunk_size;
                    let mut end_idx = 0;
                    if i == num_threads - 1 {
                        end_idx = size;
                    } else {
                        end_idx = start_idx + new_chunk_size;
                    }

                    let mut left_lock = new_left[i].lock().unwrap();
                    let mut right_lock = new_right[i].lock().unwrap();

                    *left_lock = vec![FE::zero(); end_idx - start_idx];

                    for start in (start_idx..end_idx).step_by(2*stride) {
                        for j in 0..stride {
                            let zp = roots_of_unity[((start + j) << p) & mask];
                            let a = res[start + j];
                            let b = res[start + j + stride];
                            left_lock[start + j - start_idx] = (a + zp * b);
                            left_lock[start + j + stride - start_idx] = (a - zp * b);
                        }
                    }
                });

            (0..(size/new_chunk_size)).into_iter()
                .for_each(|i| {
                    let start_idx = i * new_chunk_size;
                    let mut end_idx = 0;
                    if i == num_threads - 1 {
                        end_idx = size;
                    } else {
                        end_idx = start_idx + new_chunk_size;
                    }
                    res[start_idx..end_idx].copy_from_slice(&new_left[i].lock().unwrap());
                });

            // res.par_chunks_mut(chunk_size)
            //     .enumerate()
            //     .for_each(|(i, chunk)| {
            //         chunk.par_chunks_mut(2*stride).enumerate().for_each(|(i, small_chunk)| {
            //             for j in 0..stride {
            //                 let zp = roots_of_unity[(j << p) & mask];
            //                 let a = small_chunk[j];
            //                 let b = small_chunk[j + stride];
            //                 small_chunk[j] = a + zp * b;
            //                 small_chunk[j + stride] = a - zp * b;
            //             }
            //         });
            //     });
            // println!("Time for case 2: {:?}", start.elapsed());
        }

        stride *= 2;
        p -= 1;
    }

    res
}

pub fn hash_leaves(unhashed_leaves: &[[FE; 2]]) -> Vec<[u8; 32]> {
    let num_threads = current_num_threads();
    let len = unhashed_leaves.len();
    let chunk_size = len / num_threads;
    let remainder = len % num_threads;

    // Create a vector of `num_threads` separate vectors for `hashed_leaves`
    let hashed_leaves_vecs: Vec<Arc<Mutex<Vec<[u8; 32]>>>> = (0..num_threads)
        .map(|_| Arc::new(Mutex::new(Vec::new())))
        .collect();

    let start = Instant::now();

    // Use Rayon to process data in chunks in parallel
    (0..num_threads).into_par_iter().for_each(|i| {
        let start_idx = i * chunk_size;
        let mut end_idx = 0;
        if i == num_threads - 1 {
            end_idx = len;
        } else {
            end_idx = start_idx + chunk_size;
        }

        let chunk_unhashed = &unhashed_leaves[start_idx..end_idx];

        let start = Instant::now();
        // Compute the hashes for the chunk of data
        let local_hashed_chunk: Vec<[u8; 32]> = chunk_unhashed.iter().map(|unhashed| {
            let mut hasher = Keccak256::new();
            hasher.update(unhashed[0].as_bytes());
            hasher.update(unhashed[1].as_bytes());
            let mut hashed = [0u8; 32]; 
            hashed.copy_from_slice(&hasher.clone().finalize());
            hashed
        }).collect();

        println!("Time for cpu {:?} with len {}: {:?}", get_current_cpu(), chunk_unhashed.len(), start.elapsed());

        // Lock the corresponding thread's hashed_leaves vector and append the result
        let mut hashed_leaves_lock = hashed_leaves_vecs[i].lock().unwrap();
        hashed_leaves_lock.extend(local_hashed_chunk);
    });

    println!("Time for hashing leaves: {:?}", start.elapsed());

    // Concatenate all the results into a single vector
    let mut final_hashed_leaves = Vec::with_capacity(len);
    for hashed_vec in hashed_leaves_vecs {
        let hashed_vec_lock = hashed_vec.lock().unwrap();
        final_hashed_leaves.extend_from_slice(&hashed_vec_lock);
    }

    final_hashed_leaves
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