// for sender to generate 100 GGm trees with 16 leaves: 41.2 ms

extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rand;

use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::spfss_sender::SpfssSenderFp;
use psiri_vole::preot::OTPre;
use psiri_vole::base_cot::BaseCot;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use std::net::TcpStream;
use rand::random;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize BaseCot for the sender (ALICE)
    let mut sender_cot = BaseCot::new(0, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(&mut channel, None);

    // Original COT generation
    const depth: usize = 4;
    let size = depth - 1; // Number of COTs
    let times = 100;
    // New COT generation using OTPre
    let mut sender_pre_ot = OTPre::new(size, times);
    sender_cot.cot_gen_preot(&mut channel, &mut sender_pre_ot, size*times, None);

    let delta = rand_field_element();
    let gamma = rand_field_element();
    channel.send_stark252(&[delta.clone(), gamma.clone()]).expect("Failed to send delta and gamma");
    let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];

    let start = Instant::now();
    for i in 0..times {
        sender_pre_ot.choices_sender(&mut channel);
    }
    channel.flush();
    sender_pre_ot.reset();

    for i in 0..times {
        // Initialize Spfss for the sender
        let mut sender_spfss = SpfssSenderFp::new(depth);

        sender_spfss.compute(&mut ggm_tree_mem, delta, gamma);
        sender_spfss.send(&mut channel, &mut sender_pre_ot, 0);
        channel.flush();

        // sender_spfss.consistency_check(&mut channel, gamma);
    }
    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

}