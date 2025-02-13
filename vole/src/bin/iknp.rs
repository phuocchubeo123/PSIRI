extern crate psiri_vole;
extern crate rand;

use psiri_vole::iknp::IKNP;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use std::env;
use std::net::{TcpListener, TcpStream};
use rand::Rng;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver logic
        // Bind and wait for a connection from the sender
        let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind to address");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut io = TcpChannel::new(stream);

        let mut receiver_iknp = IKNP::new(true);
        receiver_iknp.setup_recv(&mut io, None, None, &mut comm);

        const length: usize = 3000;
        let mut data = vec![[0u8; 32]; length];
        let mut rng = rand::thread_rng();
        let r: [bool; length] = [(); length].map(|_| rng.gen_bool(0.5)); // Example choice bits

        receiver_iknp.recv_cot(&mut io, &mut data, &r, length, &mut comm);

        data = vec![[0u8; 32]; length];
        receiver_iknp.recv_cot(&mut io, &mut data, &r, length, &mut comm);

        data = vec![[0u8; 32]; length];
        receiver_iknp.recv_cot(&mut io, &mut data, &r, length, &mut comm);
    } else if role == "sender" {
        // Sender logic
        // Establish connection to the receiver
        let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to receiver");
        let mut io = TcpChannel::new(stream);

        let mut sender_iknp = IKNP::new(true);

        sender_iknp.setup_send(&mut io, None, None, &mut comm);

        let length = 3000;
        let mut data = vec![[0u8; 32]; length];
        sender_iknp.send_cot(&mut io, &mut data, length, &mut comm);

        data = vec![[0u8; 32]; length];
        sender_iknp.send_cot(&mut io, &mut data, length, &mut comm);

        data = vec![[0u8; 32]; length];
        sender_iknp.send_cot(&mut io, &mut data, length, &mut comm);
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
