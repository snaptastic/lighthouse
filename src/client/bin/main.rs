extern crate sodiumoxide;
extern crate serde;
//extern crate serde_json;
extern crate uuid;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::{thread, time};

use sodiumoxide::crypto::kx::*;
use sodiumoxide::crypto::secretbox::*;

use serde::{Deserialize, Serialize};

use uuid::Uuid;

#[derive(Debug)]
struct AgentConfiguration {
    agent_uuid: uuid::Uuid,
    rx: Key,
    tx: Key,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Debug)]
struct InitialClientInfo {
    client_public_key: PublicKey,
    agent_uuid: uuid::Uuid,    
}

#[derive(Serialize, Deserialize, Debug)]
struct InitialServerInfo {
    server_public_key: PublicKey,
    nonce: Nonce,    
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
        
        let c = seal(m, &client_keys.nonce, &client_keys.tx);

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
    }

    Ok(())
}

fn key_exchange(connection: &TcpStream) -> Result<AgentConfiguration, io::Error> {
    let (client_public_key, client_secret_key) = gen_keypair();
    let client_uuid = Uuid::new_v4();
    println!("{}", client_uuid);

    let client_initial_info = InitialClientInfo {
        client_public_key: client_public_key,
        agent_uuid: client_uuid,
    };
    let serialized_client_initial_info = serde_json::to_string(&client_initial_info).unwrap();

    send(&connection, &serialized_client_initial_info.as_bytes())?;
    println!("Sending UUID {:?} and key: {:?}", client_initial_info.agent_uuid, client_initial_info.client_public_key.0);
    
    let server_public_key = recv(&connection)?;
    println!("Receiving server pk: {:?}", server_public_key);
    let server_public_key = match sodiumoxide::crypto::kx::x25519blake2b::PublicKey::from_slice(&server_public_key) {
        Some(v) => v,
        None => {
            panic!("Failed to convert server public key");
        },
    };

    // client deduces the two session keys rx1 and tx1
    let (rx, tx) = match client_session_keys(&client_public_key, &client_secret_key, &server_public_key) {
        Ok((rx, tx)) => (rx, tx),
        Err(error) => panic!("bad server signature: {:?}", error),
    };

    let nonce = recv(&connection)?;
    let nonce = match Nonce::from_slice(&nonce){
        Some(v) => v,
        None => {
            panic!("Failed to convert nonce");
        }
    };


    let key2 = match Key::from_slice(&rx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    let key1 = match Key::from_slice(&tx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    Ok(AgentConfiguration {
        agent_uuid: client_uuid,
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