extern crate snow;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use snow::Builder;

fn main() {
    let mut buffer = vec![0u8; 65535];

    let builder: Builder = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise = builder
        .local_private_key(&static_key)
        .build_initiator().unwrap();
    
    // Connect to our server, which is hopefully listening.
    let mut connection = TcpStream::connect("127.0.0.1:12345").unwrap();
    println!("connected...");

    // -> e
    let len = noise.write_message(&[], &mut buffer).unwrap();
    send(&mut connection, &buffer[..len]);
    
    // <- e, ee
    noise.read_message(&recv(&mut connection).unwrap(), &mut buffer).unwrap();

    let mut noise = noise.into_transport_mode().unwrap();
    println!("Connection established...");

    // Get to the important business of sending secured data.
    for _ in 0..10 {
        let len = noise.write_message(b"HACK THE PLANET", &mut buffer).unwrap();
        send(&mut connection, &buffer[..len]);
    }
    println!("notified server of intent to hack planet.");
    
}

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf)?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..])?;
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
fn send(stream: &mut TcpStream, buf: &[u8]) {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    stream.write_all(&msg_len_buf).unwrap();
    stream.write_all(buf).unwrap();
}