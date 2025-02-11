extern crate psiri_vole;

use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::base_cot::BaseCot;
use psiri_vole::preot::OTPre;
use std::net::TcpStream;

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize BaseCot for the sender (ALICE)
    let mut sender_cot = BaseCot::new(0, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(&mut channel, None);

    // Original COT generation
    let size = 60; // Number of COTs
    let times = 100;
    let mut original_ot_data = vec![[0u8; 32]; size];

    let mut sender_pre_ot = OTPre::new(size, times);
    sender_cot.cot_gen_preot(&mut channel, &mut sender_pre_ot, size*times, None);
    for s in 0..times {
        sender_pre_ot.choices_sender(&mut channel);
    }
    channel.flush();
    sender_pre_ot.reset();

    for s in 0..times {
        // Send data using OTPre
        let mut m0 = vec![[0u8; 32]; size];
        let mut m1 = vec![[0u8; 32]; size];
        for i in 0..size {
            m0[i] = [i as u8; 32];
            m1[i] = [(i + 1) as u8; 32];
        }
        sender_pre_ot.send(&mut channel, &m0, &m1, size, s);
    }
}
