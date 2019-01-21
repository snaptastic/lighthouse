extern crate sodiumoxide;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::aead;

fn main() {
    let mut buffer = vec![0u8; 65535];
    sodiumoxide::init();

    let (client_pk, client_sk) = kx::gen_keypair();

    // Connect to our server, which is hopefully listening.
    let mut connection = TcpStream::connect("127.0.0.1:12345").unwrap();
    println!("connected...");

    send(&mut connection, &client_pk.0);
    println!("Sending key: {:?}", client_pk.0);


    
    let server_pk = match recv(&mut connection) {
        Ok(v) => v,
        Err(e) => {
            panic!("Error receiving server key");
        },
    };

    println!("Receiving server pk: {:?}", server_pk);
    let server_pk = match sodiumoxide::crypto::kx::x25519blake2b::PublicKey::from_slice(&server_pk) {
        Some(v) => v,
        None => {
            panic!("Failed to convert server public key");
        },
    };

    // client deduces the two session keys rx1 and tx1
    let (rx, tx) = match kx::client_session_keys(&client_pk, &client_sk, &server_pk) {
        Ok((rx, tx)) => (rx, tx),
        Err(()) => panic!("bad server signature"),
    };

    println!("Rx {:?}, Tx {:?}", rx, tx);

    //println!("notified server of intent to hack planet.");
    //let n = aead::gen_nonce();
    let nonce = recv(&mut connection);
    let rx = match aead::Key::from_slice(&rx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };
    let c = recv(&mut connection).unwrap();
    let m2 = aead::open(&c, None, &n, &rx).unwrap();
    println!("Message {:?}", m2);
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