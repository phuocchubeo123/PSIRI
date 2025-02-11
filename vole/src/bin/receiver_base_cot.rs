extern crate psiri_vole;

use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::base_cot::BaseCot;
use psiri_vole::preot::OTPre;
use std::net::TcpListener;
use std::time::Instant;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
    println!("Waiting for sender...");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Initialize BaseCot for the receiver (BOB)
    let mut receiver_cot = BaseCot::new(1, false);

    // Set up the receiver's precomputation phase
    receiver_cot.cot_gen_pre(&mut channel, None);

    // Original COT generation
    let size = 60; // Number of COTs
    let times = 100;
    let mut original_ot_data = vec![[0u8; 32]; size];
    let mut choice_bits = vec![false; size];

    let mut receiver_pre_ot = OTPre::new(size, times);
    receiver_cot.cot_gen_preot(&mut channel, &mut receiver_pre_ot, size * times, None);

    let start = Instant::now();
    for s in 0..times {
        receiver_pre_ot.choices_recver(&mut channel, &choice_bits);
    }
    channel.flush();
    receiver_pre_ot.reset();
    // Receive data using OTPre
    for s in 0..times {
        let mut received_data = vec![[0u8; 32]; size];
        receiver_pre_ot.recv(&mut channel, &mut received_data, &choice_bits, size, s);
    }
    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

}
