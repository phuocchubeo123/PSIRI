use crate::error::Result;
use crate::utils::*;

use sp_core::U256;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use sha3::{Digest, Sha3_256};

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;


pub type Pair<K, V> = (K, V);

pub trait Okvs {
    fn encode(&self, input: &Vec<Pair<FE, FE>>) -> Result<Vec<FE>>;
    fn decode(&self, encoding: &Vec<FE>, key: &[FE]) -> Vec<FE>;
}
