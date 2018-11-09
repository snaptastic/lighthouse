use std::io::prelude::*;
use std::net::TcpStream;
extern crate sodiumoxide;
use sodiumoxide::crypto::box_;

fn main() {
    let init = sodiumoxide::init();
    match init {
        Ok(s) => s,
        Err(_) => panic!("Failed to initialize"),
    }
    
    let mut connection = TcpStream::connect("127.0.0.1:12345")
                                   .expect("Error connecting");
        
    let (ourpk, oursk) = box_::gen_keypair();
    let nonce = box_::gen_nonce();
    let _ = connection.write(&ourpk.0);
    
    let plaintext = b"Test Message\n";

    let mut theirpk_bytes = [0; 32];
    connection.read(&mut theirpk_bytes).unwrap();

    let theirpk = box_::PublicKey(theirpk_bytes);
    let ciphertext = box_::seal(plaintext, &nonce, &theirpk, &oursk);

    let _ = connection.write(&ciphertext);

}
