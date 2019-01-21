extern crate sodiumoxide;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::net::TcpListener;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::aead;

fn main () {
    sodiumoxide::init();

    // Wait on our client's arrival...
    println!("listening on 127.0.0.1:12345");

    let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
    let (connection, _) = listener.accept().unwrap();
    println!("Connection Established!");
    handle_connection(connection);
}

fn handle_connection(mut connection: TcpStream) {
    let mut buffer = vec![0u8; 65535];
    let n = aead::gen_nonce();
    let (server_pk, server_sk) = kx::gen_keypair();

    let client_pk = match recv(&mut connection) {
        Ok(v) => v,
        Err(e) => {
            panic!("Error receiving client key");
        },
    };

    let client_pk = match sodiumoxide::crypto::kx::x25519blake2b::PublicKey::from_slice(&client_pk) {
        Some(v) => v,
        None => {
            panic!("Failed to convert client public key");
        },
    };
    println!("Received client public key: {:?}", client_pk);

    println!("Sending server public key: {:?}", server_pk.0);
    send(&mut connection, &server_pk.0);

    // server performs the same operation
    let (rx, tx) = match kx::server_session_keys(&server_pk, &server_sk, &client_pk) {
        Ok((rx, tx)) => (rx, tx),
        Err(()) => panic!("bad client signature"),
    };

    println!("Rx {:?}, Tx {:?}", rx, tx);

    let nonce = recv(&mut connection);
    let m = b"Some plaintext";
    let ad = b"Some additional data";
    let tx = match aead::Key::from_slice(&tx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };
    let c = aead::seal(m, None, &n, &tx);

    send(&mut connection, &c);

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