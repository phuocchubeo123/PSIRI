extern crate psiri_vole;
extern crate lambdaworks_math;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::vole_triple::{VoleTriple, PHUOC_LPN};
use std::net::TcpListener;
use std::time::Instant;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    let mut vole = VoleTriple::new(1, true, &mut channel, PHUOC_LPN);
    
    let start = Instant::now();
    vole.setup_receiver(&mut channel);
    println!("Time taken for setup: {:?}", start.elapsed());

    vole.extend_initialization();

    const size: usize = 100_000;
    let mut y = [FE::zero(); size];
    let mut z = [FE::zero(); size];
    let start = Instant::now();
    vole.extend(&mut channel, &mut y, &mut z, size);
    println!("Time taken for one extend: {:?}", start.elapsed());
}