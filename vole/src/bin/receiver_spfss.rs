extern crate psiri_vole; 
extern crate lambdaworks_math;
extern crate rand;

use psiri_vole::spfss_receiver::SpfssRecverFp;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::base_cot::BaseCot;
use psiri_vole::preot::OTPre;
use psiri_vole::utils::rand_field_element;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use std::net::TcpListener;
use rand::random;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

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
    const depth: usize = 4;
    let size = depth - 1; // Number of COTs
    let times = 100;
    let mut choice_bits = vec![false; size*times];
    // Populate random choice bits
    for bit in &mut choice_bits {
        *bit = rand::random();
    }

    // New COT generation using OTPre
    let mut receiver_pre_ot = OTPre::new(size, times);
    receiver_cot.cot_gen_preot(&mut channel, &mut receiver_pre_ot, size*times, Some(&choice_bits));

    let received_data = channel.receive_stark252(2).expect("Failed to receive delta and gamma");
    let delta = received_data[0];
    let gamma = received_data[1];

    let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];
    for i in 0..times {
        receiver_pre_ot.choices_recver(&mut channel, &[false; depth - 1]);
    }
    channel.flush();
    receiver_pre_ot.reset();

    for i in 0..times {
        let beta = rand_field_element();
        let delta2 = gamma + delta * beta;
        // Initialize Spfss for the sender
        let mut receiver_spfss = SpfssRecverFp::new(depth);

        receiver_spfss.recv(&mut channel, &mut receiver_pre_ot, 0);
        receiver_spfss.compute(&mut ggm_tree_mem, delta2);
        // receiver_spfss.consistency_check(&mut channel, delta2, beta);
    }
}