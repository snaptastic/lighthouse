extern crate snow;
extern crate lighthouse;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::net::TcpListener;
use snow::Builder;
use lighthouse::ThreadPool;

fn main() {
    let pool = ThreadPool::new(4);

    // Wait on our client's arrival...
    println!("listening on 127.0.0.1:12345");

    let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(v) => v,
            Err(e) => panic!("Error accepting client: {:?}", e)
        };

        pool.execute(|| {
            handle_connection(stream);
        });
    }
}

fn handle_connection(mut connection: TcpStream) {
    let mut buffer = vec![0u8; 65535];

    let builder: Builder = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key = builder.generate_keypair().unwrap();
    let mut noise = builder
        .local_private_key(&static_key.private)
        .build_responder().unwrap();


    // <- e
    noise.read_message(&recv(&mut connection).unwrap(), &mut buffer).unwrap();

    // -> e, ee
    let len = noise.write_message(&[0u8; 0], &mut buffer).unwrap();
    send(&mut connection, &buffer[..len]);

    let mut noise = noise.into_transport_mode().unwrap();

     while let Ok(msg) = recv(&mut connection) {
        let len = noise.read_message(&msg, &mut buffer).unwrap();
        println!("client said: {}", String::from_utf8_lossy(&buffer[..len]));
    }
    println!("connection closed.");

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