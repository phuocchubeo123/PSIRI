use p256::EncodedPoint;

use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub trait CommunicationChannel {
    fn send_u8(&mut self, data: &[u8]) -> std::io::Result<()>;
    fn receive_u8(&mut self) -> std::io::Result<Vec<u8>>;
    fn send_block<const N: usize>(&mut self, data: &[[u8; N]]);
    fn receive_block<const N: usize>(&mut self) -> Vec<[u8; N]>;
    fn send_bits(&mut self, bits: &[bool]) -> std::io::Result<()>;
    fn receive_bits(&mut self) -> std::io::Result<Vec<bool>>;
    fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<()>;
    fn receive_stark252(&mut self, count: usize) -> std::io::Result<Vec<FE>>;
    fn send_point(&mut self, point: &EncodedPoint);
    fn receive_point(&mut self) -> EncodedPoint;
    fn flush(&mut self);
}