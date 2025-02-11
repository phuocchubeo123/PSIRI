extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rayon;

use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::vole_triple::PHUOC_LPN;
use psiri_vole::psi_receiver::OprfReceiver;
use psiri_vole::utils::rand_field_element;
use std::net::TcpListener;
use std::time::Instant;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
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
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    let size = 1<<16;
    let mut oprf = OprfReceiver::new(&mut channel, size, true, PHUOC_LPN);

    let data = (0..size).map(|_| rand_field_element()).collect::<Vec<FE>>();

    // Send some elements to Sender for test
    channel.send_stark252(&data).expect("Failed to send data to sender");

    let start_protocol = Instant::now();

    let start = Instant::now();
    oprf.commit_P(&data);
    println!("P commit time: {:?}", start.elapsed());

    oprf.send_P_commit(&mut channel);
    oprf.receive_X_commit(&mut channel);

    let mut outputs = vec![FE::zero(); size];
    oprf.receive(&mut channel, &data);
    println!("Whole protocol time: {:?}", start_protocol.elapsed());
}