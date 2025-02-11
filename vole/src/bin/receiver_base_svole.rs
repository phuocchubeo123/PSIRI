extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rand;

use std::net::TcpListener;
use std::time::Instant;
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::base_svole::BaseSvole;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
    println!("Waiting for sender...");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Set up BaseSvole
    let mut receiver_svole = BaseSvole::new_receiver(&mut channel);

    // Test triple generation
    let batch_size = 20000;
    let mut shares = vec![FE::zero(); batch_size];
    let mut u_batch = vec![FE::zero(); batch_size];

    let start = Instant::now();

    receiver_svole.triple_gen_recv(&mut channel, &mut shares, &mut u_batch, batch_size);

    let duration = start.elapsed();
    println!("Triple generation (recv) time: {:?}", duration);
}
