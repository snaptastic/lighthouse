extern crate sodiumoxide;

use std::io::{self, Read, Write};//, Error, ErrorKind};
use std::net::TcpStream;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::aead;
use sodiumoxide::crypto::aead::Key;

use std::{thread, time};

#[derive(Debug)]
struct KeyMaterial {
    rx: Key,
    tx: Key,
    nonce: aead::Nonce,
}

fn main() -> Result<(), Box<std::error::Error>> {
    //let buffer = vec![0u8; 65535];
    sodiumoxide::init().expect("Unable to initialise NACL");
    let fifteen_secs = time::Duration::new(15, 0);

    // Connect to our server, which is hopefully listening.
    let mut connection = TcpStream::connect("127.0.0.1:12345").unwrap();
    println!("connected...");

    let client_keys = match key_exchange(&connection){
        Ok(keys) => keys,
        Err(error) => match error.kind() {
            io::ErrorKind::BrokenPipe => {
                println!("Error: {:?}", error);
                return Ok(());
            },
            error => panic!("Error: {:?}", error),
        }
    };

    loop {
        let m = b"Some plaintext";
        //let ad = b"Some additional data";
        
        let c = aead::seal(m, None, &client_keys.nonce, &client_keys.tx);

        match send(&mut connection, &c){
            Ok(_) => {
                thread::sleep(fifteen_secs);
                continue
            },
            Err(error) => match error.kind() {
            io::ErrorKind::BrokenPipe => {
                println!("Error: {:?}", error);
                break;
            },
            error => panic!("Error: {:?}", error),
        }

        };

        /*
        let c = recv(&mut connection).unwrap();
        let m2 = aead::open(&c, None, &nonce, &rx).unwrap();
        println!("Message: {}", String::from_utf8(m2).expect("Invalid utf-8"));
        */

    }

    Ok(())
}

fn key_exchange(connection: &TcpStream) -> Result<KeyMaterial, io::Error> {
    //let custom_error = Error::new(ErrorKind::BrokenPipe, "Connection disconnect");
    let (client_pk, client_sk) = kx::gen_keypair();

    send(&connection, &client_pk.0)?;
    println!("Sending key: {:?}", client_pk.0);
    
    let server_pk = recv(&connection)?;

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
        Err(error) => panic!("bad server signature: {:?}", error),
    };

    let nonce = recv(&connection)?;
    let nonce = match aead::Nonce::from_slice(&nonce){
        Some(v) => v,
        None => {
            panic!("Failed to convert nonce");
        }
    };


    let key2 = match aead::Key::from_slice(&rx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    let key1 = match aead::Key::from_slice(&tx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    Ok(KeyMaterial {
        tx: key1,
        rx: key2,
        nonce: nonce,
    })
}


/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(mut stream: &TcpStream) -> io::Result<Vec<u8>> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf)?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..])?;
    
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
fn send(mut stream: &TcpStream, buf: &[u8]) -> io::Result<()> {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    stream.write_all(&msg_len_buf)?;
    stream.write_all(buf)?;

    Ok(())
}