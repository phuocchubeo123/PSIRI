extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rand;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::cope::Cope;
use psiri_vole::utils::rand_field_element;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut receiver_cope = Cope::new(1, m);

    // Receiver initializes
    receiver_cope.initialize_receiver(&mut channel);

    // Generate a random u
    let u = rand_field_element();
    println!("Receiver u: {}", u);

    // Test extend
    let single_result = receiver_cope.extend_receiver(&mut channel, u);
    receiver_cope.check_triple(&mut channel, &[u], &[single_result], 1);

    // // Test extend
    // let single_result = receiver_cope.extend_receiver(u);
    // receiver_cope.check_triple(&[u], &[single_result], 1);

    let start = Instant::now();

    // Test extend_batch
    let batch_size = 20000;
    let u_batch: Vec<FE> = (0..batch_size).map(|_| rand_field_element()).collect();
    let mut batch_result = vec![FE::zero(); batch_size];
    receiver_cope.extend_receiver_batch(&mut channel, &mut batch_result, &u_batch, batch_size);

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

    receiver_cope.check_triple(&mut channel, &u_batch, &batch_result, batch_size);

}
