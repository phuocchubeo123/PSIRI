// extern crate psiri_vole;
// extern crate lambdaworks_math;
// extern crate rayon;

// use psiri_vole::socket_channel::TcpChannel;
// use psiri_vole::comm_channel::CommunicationChannel;
// use psiri_vole::psi_sender::OprfSender;
// use psiri_vole::vole_triple::PHUOC_LPN;
// use std::net::TcpStream;
// use std::time::Instant; 
// use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
// use lambdaworks_math::field::element::FieldElement;
// use lambdaworks_math::field::traits::IsPrimeField;
// use rayon::ThreadPoolBuilder;
// use rayon::current_num_threads;

// pub type F = Stark252PrimeField;
// pub type FE = FieldElement<F>;

// fn main() {
//     ThreadPoolBuilder::new()
//         .num_threads(8)  // Change this number to your preference
//         .build_global()
//         .unwrap();
//     let num_threads = current_num_threads();
//     println!("🚀 Rayon is using {} threads", num_threads);
//     // Connect to the receiver
//     let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
//     let mut channel = TcpChannel::new(stream);

//     let size = 1<<20;

//     let mut oprf = OprfSender::new(&mut channel, size, true, PHUOC_LPN);

//     let data = channel.receive_stark252(size).expect("Failed to receive data for test from receiver");

//     let start = Instant::now();
//     oprf.commit_X(&data);
//     println!("X commit time: {:?}", start.elapsed());

//     oprf.receive_P_commit(&mut channel);
//     oprf.send_X_commit(&mut channel);

//     let start = Instant::now(); 
//     oprf.send(&mut channel, &data);
//     println!("Send time: {:?}", start.elapsed());
// }

extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rayon;
extern crate clap;

use clap::{Command, Arg};
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::psi_sender::OprfSender;
use psiri_vole::psi_receiver::OprfReceiver;
use psiri_vole::vole_triple::PHUOC_LPN;
use psiri_vole::utils::rand_field_element;
use std::net::{TcpStream, TcpListener};
use std::time::Instant;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use rayon::ThreadPoolBuilder;
use rayon::current_num_threads;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Command-line argument parsing
    let matches = Command::new("PSI Protocol")
        .version("1.0")
        .author("Your Name")
        .about("Sender and receiver for PSI protocol")
        .arg(
            Arg::new("role")
                .help("Role of this instance (sender or receiver)")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("address")
                .help("Address of the other party (e.g., 127.0.0.1)")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("port")
                .help("Port to connect on (e.g., 8080)")
                .required(true)
                .index(3),
        )
        .get_matches();

    let role = matches.get_one::<String>("role").unwrap();
    let address = matches.get_one::<String>("address").unwrap();
    let port = matches.get_one::<String>("port").unwrap();
    
    ThreadPoolBuilder::new()
        .num_threads(8) // Adjust the number of threads as needed
        .build_global()
        .unwrap();
    
    let num_threads = current_num_threads();
    println!("🚀 Rayon is using {} threads", num_threads);

    if role == "sender" {
        // Sender logic
        println!("Starting as Sender...");
        let stream = TcpStream::connect(format!("{}:{}", address, port))
            .expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        let size = 1 << 20;  // Example size
        let mut oprf = OprfSender::new(&mut channel, size, true, PHUOC_LPN);

        let data = channel.receive_stark252(size).expect("Failed to receive data from receiver");

        let start = Instant::now();
        oprf.commit_X(&data);
        println!("X commit time: {:?}", start.elapsed());

        oprf.receive_P_commit(&mut channel);
        oprf.send_X_commit(&mut channel);

        let start = Instant::now();
        oprf.send(&mut channel, &data);
        println!("Send time: {:?}", start.elapsed());
    } else if role == "receiver" {
        // Receiver logic
        println!("Starting as Receiver...");
        let listener = TcpListener::bind(format!("{}:{}", address, port))
            .expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        let size = 1 << 20;  // Example size
        let mut oprf = OprfReceiver::new(&mut channel, size, true, PHUOC_LPN);

        let data = (0..size).map(|_| rand_field_element()).collect::<Vec<FE>>();

        // Send data to Sender for test
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
    } else {
        eprintln!("Invalid role. Use 'sender' or 'receiver'.");
        std::process::exit(1);
    }
}
