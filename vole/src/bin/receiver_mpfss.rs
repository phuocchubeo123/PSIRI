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
use std::net::TcpListener;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    const log_bin_sz: usize = 4;
    const t: usize = 100;
    const n: usize = t * (1 << log_bin_sz);
    const k: usize = 2;

    // Initialize BaseCot for the sender (ALICE)
    let mut receiver_cot = BaseCot::new(1, false);

    // Set up the sender's precomputation phase
    receiver_cot.cot_gen_pre(&mut channel, None);
    let mut pre_ot = OTPre::new(log_bin_sz, t);
    receiver_cot.cot_gen_preot(&mut channel, &mut pre_ot, log_bin_sz*t, None);

    let mut mac = vec![FE::zero(); t+1];
    let mut u = vec![FE::zero(); t+1];

    // Base sVOLE first
    let mut svole = BaseSvole::new_receiver(&mut channel);
    // mac = key + delta * u
    svole.triple_gen_recv(&mut channel, &mut mac, &mut u, t+1);

    let mut y = vec![FE::zero(); n];
    let mut z = vec![FE::zero(); n];
    let mut mpfss = MpfssReg::new(n, t, log_bin_sz, 1);
    mpfss.set_malicious();

    mpfss.receiver_init();
    mpfss.mpfss_receiver(&mut channel, &mut pre_ot, &mac, &u, &mut y, &mut z);
}