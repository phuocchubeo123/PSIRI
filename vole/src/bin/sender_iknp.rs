extern crate psiri_vole;

use psiri_vole::iknp::IKNP;
use psiri_vole::comm_channel::CommunicationChannel;
use psiri_vole::socket_channel::TcpChannel;
use std::net::TcpStream;

fn main() {
    // Establish connection to the receiver
    let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to receiver");
    let mut io = TcpChannel::new(stream);


    let mut sender_iknp = IKNP::new(true);
    
    sender_iknp.setup_send(&mut io, None, None);

    let length = 3000;
    let mut data = vec![[0u8; 32]; length];
    sender_iknp.send_cot(&mut io, &mut data, length);

    // println!("Sender COT data:");
    // for i in 0..10 {
    //     println!("{:?}", &data[i]);
    // }

    data = vec![[0u8; 32]; length];
    sender_iknp.send_cot(&mut io, &mut data, length);

    // println!("Sender COT data:");
    // for i in 0..10 {
    //     println!("{:?}", &data[i]);
    // }

    data = vec![[0u8; 32]; length];
    sender_iknp.send_cot(&mut io, &mut data, length);

    // println!("Sender COT data:");
    // for i in 0..10 {
    //     println!("{:?}", &data[i]);
    // }
}
