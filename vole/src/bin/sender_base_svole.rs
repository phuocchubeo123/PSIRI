extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rand;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::base_svole::BaseSvole;
use psiri_vole::utils::rand_field_element;
use std::net::TcpStream;
use std::time::Instant;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Set up BaseSvole
    let delta = rand_field_element();
    println!("Sender Delta: {}", delta);

    let mut sender_svole = BaseSvole::new_sender(&mut channel, delta);

    // Test triple generation
    let batch_size = 20000;
    let mut shares = vec![FE::zero(); batch_size];

    let start = Instant::now();

    sender_svole.triple_gen_send(&mut channel, &mut shares, batch_size);

    let duration = start.elapsed();
    println!("Triple generation (send) time: {:?}", duration);
}
