extern crate psiri_vole;
extern crate lambdaworks_math;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::vole_triple::{FP_DEFAULT, VoleTriple, MILLION_LPN};
use psiri_vole::utils::rand_field_element;
use std::net::TcpStream;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    let mut vole = VoleTriple::new(0, true, &mut channel, MILLION_LPN);

    let delta = rand_field_element();
    vole.setup_sender(&mut channel, delta);

    vole.extend_initialization();

    const size: usize = 100_000;
    let mut y = [FE::zero(); size];
    let mut z = [FE::zero(); size];
    vole.extend(&mut channel, &mut y, &mut z, size);
}