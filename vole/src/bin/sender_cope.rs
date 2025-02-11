extern crate psiri_vole;
extern crate lambdaworks_math;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::cope::Cope;
use psiri_vole::utils::rand_field_element;
use std::net::TcpStream;
use std::time::Instant;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut sender_cope = Cope::new(0, m);

    // Generate a random delta
    let delta = rand_field_element();
    println!("Sender delta: {}", delta);

    // Sender initializes with delta
    sender_cope.initialize_sender(&mut channel, delta);

    // Test extend
    let single_result = sender_cope.extend_sender(&mut channel);
    sender_cope.check_triple(&mut channel, &[delta], &[single_result], 1);

    // // Test extend
    // let single_result = sender_cope.extend_sender();
    // sender_cope.check_triple(&[delta], &[single_result], 1);

    let start = Instant::now();

    // Test extend_batch
    let batch_size = 20000;
    let mut batch_result = vec![FE::zero(); batch_size];
    sender_cope.extend_sender_batch(&mut channel, &mut batch_result, batch_size);

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

    sender_cope.check_triple(&mut channel, &[delta], &batch_result, batch_size);

}
