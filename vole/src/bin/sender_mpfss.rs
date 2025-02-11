extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rand;

use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::spfss_sender::SpfssSenderFp;
use psiri_vole::preot::OTPre;
use psiri_vole::base_cot::BaseCot;
use psiri_vole::mpfss_reg::MpfssReg;
use psiri_vole::base_svole::BaseSvole;
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

    const log_bin_sz: usize = 4;
    const t: usize = 100;
    const n: usize = t * (1 << log_bin_sz);
    const k: usize = 2;

    // Initialize BaseCot for the sender (ALICE)
    let mut sender_cot = BaseCot::new(0, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(&mut channel, None);
    let mut pre_ot = OTPre::new(log_bin_sz, t);
    sender_cot.cot_gen_preot(&mut channel, &mut pre_ot, log_bin_sz*t, None);


    let delta = rand_field_element();
    let mut key = vec![FE::zero(); t+1];

    // Base sVOLE first
    let mut svole = BaseSvole::new_sender(&mut channel, delta);
    // mac = key + delta * u
    svole.triple_gen_send(&mut channel, &mut key, t+1);

    let mut y = vec![FE::zero(); n];
    let mut mpfss = MpfssReg::new(n, t, log_bin_sz, 0);
    mpfss.set_malicious();

    mpfss.sender_init(delta);

    let start = Instant::now();
    mpfss.mpfss_sender(&mut channel, &mut pre_ot, &key, &mut y);
    let duration = start.elapsed();
    println!("Time taken to generate {} Spfss: {:?}", t, duration);
}