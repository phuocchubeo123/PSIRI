extern crate psiri_vole;
extern crate rand;

use psiri_vole::iknp::IKNP;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use std::net::TcpListener;
use rand::Rng;

fn main() {
    // Bind and wait for a connection from the sender
    let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind to address");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut io = TcpChannel::new(stream);

    let mut receiver_iknp = IKNP::new(true);
    receiver_iknp.setup_recv(&mut io, None, None);

    const length: usize = 3000;
    let mut data = vec![[0u8; 32]; length];
    let mut rng = rand::thread_rng();
    let r: [bool; length] = [(); length].map(|_| rng.gen_bool(0.5)); // Example choice bits

    receiver_iknp.recv_cot(&mut io, &mut data, &r, length);

    // println!("Choice bits: {:?}", &r[0..10]);
    // println!("Receiver COT data:");
    // for i in 0..10 {
    //     println!("{:?}", &data[i]);
    // }

    data = vec![[0u8; 32]; length];
    receiver_iknp.recv_cot(&mut io, &mut data, &r, length);
    // println!("Choice bits: {:?}", &r[0..10]);
    // println!("Receiver COT data:");
    // for i in 0..10 {
    //     println!("{:?}", &data[i]);
    // }

    data = vec![[0u8; 32]; length];
    receiver_iknp.recv_cot(&mut io, &mut data, &r, length);
    // println!("Choice bits: {:?}", &r[0..10]);
    // println!("Receiver COT data:");
    // for i in 0..10 {
    //     println!("{:?}", &data[i]);
    // }
}