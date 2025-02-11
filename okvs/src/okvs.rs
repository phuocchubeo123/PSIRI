use crate::types::{Okvs, Pair};
use crate::error::Result;
use crate::utils::*;

use sp_core::U256;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::time::Instant;
use rayon::prelude::*;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

const EPSILON: f64 = 1.0; // can change
const BAND_WIDTH: usize = 80; // can change

pub struct RbOkvs {
    pub columns: usize, 
    band_width: usize,
    r1: [u8; 16],
    r2: [u8; 16],
}

impl RbOkvs {
    pub fn new(kv_count: usize, r1: &[u8; 16], r2: &[u8; 16]) -> Self {
        let columns = ((1.0 + EPSILON) * kv_count as f64) as usize;

        Self {
            columns,
            band_width: if BAND_WIDTH < columns {
                BAND_WIDTH
            } else {
                columns * 80 / 100
            },
            r1: *r1,
            r2: *r2,
        }
    }
}

impl Okvs for RbOkvs {
    fn encode(&self, input: &Vec<Pair<FE, FE>>) -> Result<Vec<FE>> {
        let start = Instant::now();
        let (matrix, start_pos, y) = self.create_sorted_matrix(input)?;
        simple_gauss(y, matrix, start_pos, self.columns, self.band_width)
    }

    fn decode(&self, encoding: &Vec<FE>, key: &[FE]) -> Vec<FE> {
        let n = key.len();
        let mut start = vec![0usize; n];
        let mut band = vec![U256::default(); n];

        let num_threads = rayon::current_num_threads();
        let chunk_size = n / num_threads;

        start.par_iter_mut().zip(band.par_iter_mut()).enumerate().for_each(|(i, (starti, bandi))| {
            *starti = hash_to_index(key[i], &self.r1, self.columns - self.band_width);
            *bandi = hash_to_band(key[i], &self.r2);
        });

        let mut res = vec![FE::zero(); n];

        res.par_iter_mut().enumerate().for_each(|(i, resi)| {
            *resi = inner_product(&band[i], &encoding[start[i]..start[i]+self.band_width]);
        });

        res
    }
}

impl RbOkvs {
    // Create the system of equations to solve, already sorted by the first non-zero index
    fn create_sorted_matrix(
        &self,
        input: &Vec<Pair<FE, FE>>,
    ) -> Result<(Vec<U256>, Vec<usize>, Vec<FE>)> {
        let n = input.len();
        let mut start_pos: Vec<(usize, usize)> = vec![(0, 0); n];
        let mut matrix: Vec<U256> = vec![U256::default(); n];
        let mut start_ids: Vec<usize> = vec![0; n];
        let mut y = vec![FE::zero(); n];

        for i in (0..(n-7)).step_by(8) {
            start_pos[i] = (i, hash_to_index(input[i].0, &self.r1, self.columns - self.band_width));
            start_pos[i+1] = (i+1, hash_to_index(input[i+1].0, &self.r1, self.columns - self.band_width));
            start_pos[i+2] = (i+2, hash_to_index(input[i+2].0, &self.r1, self.columns - self.band_width));
            start_pos[i+3] = (i+3, hash_to_index(input[i+3].0, &self.r1, self.columns - self.band_width));
            start_pos[i+4] = (i+4, hash_to_index(input[i+4].0, &self.r1, self.columns - self.band_width));
            start_pos[i+5] = (i+5, hash_to_index(input[i+5].0, &self.r1, self.columns - self.band_width));
            start_pos[i+6] = (i+6, hash_to_index(input[i+6].0, &self.r1, self.columns - self.band_width));
            start_pos[i+7] = (i+7, hash_to_index(input[i+7].0, &self.r1, self.columns - self.band_width));
        }

        for i in (n - n % 8)..n {
            start_pos[i] = (i, hash_to_index(input[i].0, &self.r1, self.columns - self.band_width));
        }

        radix_sort(&mut start_pos, self.columns - self.band_width - 1);

        for i in (0..(n-7)).step_by(8) {
            matrix[i] = hash_to_band(input[start_pos[i].0].0, &self.r2);
            y[i] = input[start_pos[i].0].1.to_owned();
            start_ids[i] = start_pos[i].1;
            matrix[i+1] = hash_to_band(input[start_pos[i+1].0].0, &self.r2);
            y[i+1] = input[start_pos[i+1].0].1.to_owned();
            start_ids[i+1] = start_pos[i+1].1;
            matrix[i+2] = hash_to_band(input[start_pos[i+2].0].0, &self.r2);
            y[i+2] = input[start_pos[i+2].0].1.to_owned();
            start_ids[i+2] = start_pos[i+2].1;
            matrix[i+3] = hash_to_band(input[start_pos[i+3].0].0, &self.r2);
            y[i+3] = input[start_pos[i+3].0].1.to_owned();
            start_ids[i+3] = start_pos[i+3].1;
            matrix[i+4] = hash_to_band(input[start_pos[i+4].0].0, &self.r2);
            y[i+4] = input[start_pos[i+4].0].1.to_owned();
            start_ids[i+4] = start_pos[i+4].1;
            matrix[i+5] = hash_to_band(input[start_pos[i+5].0].0, &self.r2);
            y[i+5] = input[start_pos[i+5].0].1.to_owned();
            start_ids[i+5] = start_pos[i+5].1;
            matrix[i+6] = hash_to_band(input[start_pos[i+6].0].0, &self.r2);
            y[i+6] = input[start_pos[i+6].0].1.to_owned();
            start_ids[i+6] = start_pos[i+6].1;
            matrix[i+7] = hash_to_band(input[start_pos[i+7].0].0, &self.r2);
            y[i+7] = input[start_pos[i+7].0].1.to_owned();
            start_ids[i+7] = start_pos[i+7].1;
        }

        for i in (n - n % 8)..n {
            matrix[i] = hash_to_band(input[start_pos[i].0].0, &self.r2);
            y[i] = input[start_pos[i].0].1.to_owned();
            start_ids[i] = start_pos[i].1;
        }

        Ok((matrix, start_ids, y))
    }
}