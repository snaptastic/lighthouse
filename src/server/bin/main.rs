use std::io::prelude::*;
use std::net::TcpStream;
use std::net::TcpListener;
extern crate sodiumoxide;
use sodiumoxide::crypto::box_;


fn main() {
    let init = sodiumoxide::init();
    match init {
        Ok(s) => s,
        Err(_) => panic!("Failed to initialize"),
    }

    
    let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
    for connection in listener.incoming() {
        let connection = connection.unwrap();

        println!("Connection Established!");
        handle_connection(connection);
    }
}

fn handle_connection(mut connection: TcpStream) {
    let mut theirpk_bytes = [0; 32];
    let mut ciphertext = [0; 512];

    connection.read(&mut theirpk_bytes).unwrap();
    let (ourpk, oursk) = box_::gen_keypair();
    let nonce = box_::gen_nonce();

    let _ = connection.write(&ourpk.0);

    connection.read(&mut ciphertext).unwrap();
    
    let theirpk = box_::PublicKey(theirpk_bytes);
    let plaintext = box_::open(&ciphertext, &nonce, &theirpk, &oursk).unwrap();

    println!("Request: {:?}", plaintext);


}