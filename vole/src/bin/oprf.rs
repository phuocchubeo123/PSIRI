extern crate psiri_vole;
extern crate lambdaworks_math;
extern crate rayon;
extern crate clap;

use clap::{Command, Arg};
use psiri_vole::socket_channel::TcpChannel;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::psi_sender::OprfSender;
use psiri_vole::psi_receiver::OprfReceiver;
use psiri_vole::vole_triple::{MILLION_LPN, ONE_MILLION_LPN, TWO_MILLION_LPN, THREE_MILLION_LPN};
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
        .arg(
            Arg::new("log_size")
                .help("Log intersection size")
                .required(true)
                .index(4),
        )
        .arg(
            Arg::new("threads")
                .help("Set the number of threads")
                .required(true)
                .index(5)
        )
        .arg(
            Arg::new("params")
                .help("Choose LPN Param")
                .required(true)
                .index(6)
        )
        .get_matches();

    let role = matches.get_one::<String>("role").unwrap();
    let address = matches.get_one::<String>("address").unwrap();
    let port = matches.get_one::<String>("port").unwrap();
    let log_size = matches.get_one::<String>("log_size").unwrap().parse::<usize>().unwrap();
    let num_threads = matches.get_one::<String>("threads").unwrap().parse::<usize>().unwrap();
    let params_idx = matches.get_one::<String>("params").unwrap().parse::<usize>().unwrap();
    
    ThreadPoolBuilder::new()
        .num_threads(num_threads) // Adjust the number of threads as needed
        .build_global()
        .unwrap();

    println!("🚀 Rayon is using {} threads", num_threads);

    let size = 1 << log_size;
    let mut param = MILLION_LPN;
    if params_idx == 0 {
        param = MILLION_LPN;
    } else if params_idx == 1 {
        param = ONE_MILLION_LPN;
    } else if params_idx == 2 {
        param = TWO_MILLION_LPN;
    } else if params_idx == 3 {
        param = THREE_MILLION_LPN;
    }

    if role == "sender" {
        // Sender logic
        println!("Starting as Sender...");
        let stream = TcpStream::connect(format!("{}:{}", address, port))
            .expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        let data = channel.receive_stark252(size).expect("Failed to receive data from receiver");

        let mut oprf = OprfSender::new(&mut channel, size, true, param);

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

        // Send data to Sender for test
        let data = (0..size).map(|_| rand_field_element()).collect::<Vec<FE>>();

        channel.send_stark252(&data).expect("Failed to send data to sender");


        let start_protocol = Instant::now();

        let start = Instant::now();
        let mut oprf = OprfReceiver::new(&mut channel, size, true, param);
        println!("Initiate protocol took {:?}", start.elapsed());

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
