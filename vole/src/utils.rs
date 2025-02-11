use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::random;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use stark_platinum_prover::fri::Polynomial;
use rayon::prelude::*;
use rayon::current_num_threads;
use std::time::Instant;

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

        if 4*stride > chunk_size {
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

pub fn parallel_ifft(evals: &[FE], roots_of_unity_inv: &[FE], log_size: usize, log_blowup_factor: usize) -> Vec<FE> {
    let size = 1 << (log_size + log_blowup_factor);
    let mut res = parallel_fft(evals, roots_of_unity_inv, log_size, log_blowup_factor);
    let inv_size = F::get_root_of_unity(log_size + log_blowup_factor).pow(&UnsignedInteger { limbs: (size as u64).wrapping_neg() });
    res.iter_mut().for_each(|x| *x *= inv_size);
    res
}