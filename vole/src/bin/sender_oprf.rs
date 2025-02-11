extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rayon;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::psi_sender::OprfSender;
use psiri_vole::vole_triple::PHUOC_LPN;
use std::net::TcpStream;
use std::time::Instant; 
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;
use rayon::ThreadPoolBuilder;
use rayon::current_num_threads;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    ThreadPoolBuilder::new()
        .num_threads(8)  // Change this number to your preference
        .build_global()
        .unwrap();
    let num_threads = current_num_threads();
    println!("🚀 Rayon is using {} threads", num_threads);
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    let size = 1<<20;

    let mut oprf = OprfSender::new(&mut channel, size, true, PHUOC_LPN);

    let data = channel.receive_stark252(size).expect("Failed to receive data for test from receiver");

    let start = Instant::now();
    oprf.commit_X(&data);
    println!("X commit time: {:?}", start.elapsed());

    oprf.receive_P_commit(&mut channel);
    oprf.send_X_commit(&mut channel);

    let start = Instant::now(); 
    oprf.send(&mut channel, &data);
    println!("Send time: {:?}", start.elapsed());
}