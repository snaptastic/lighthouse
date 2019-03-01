extern crate sodiumoxide;
extern crate mio;
extern crate rustyline;

use std::io::{self, Read, Write, Error, ErrorKind};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, Shutdown};
use std::time::{Duration};
use std::{thread};
use std::os::unix::io::AsRawFd;

use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::aead;
use sodiumoxide::crypto::aead::Key;

use mio::{Events, Ready, Poll, PollOpt, Token};
use mio::net::{TcpStream, TcpListener};
use mio::unix::EventedFd;

use rustyline::error::ReadlineError;
use rustyline::Editor;


#[derive(Debug)]
struct Client {
    token: mio::Token,
    connection: TcpStream,
    keys: KeyMaterial,
}

#[derive(Debug)]
struct KeyMaterial {
    rx: Key,
    tx: Key,
    nonce: aead::Nonce,
}

fn main () -> Result<(), Box<std::error::Error>> {
    //let buffer = vec![0u8; 65535];
    sodiumoxide::init().unwrap();

    // Wait on our client's arrival...
    println!("listening on 127.0.0.1:12345");
    let addr = "127.0.0.1:12345".parse()?;
    let listener = TcpListener::bind(&addr).unwrap();
    
    // The main event loop
    match socket_event_loop(listener){
        Ok(_) => {
            println!("[+] Exiting...");

            return Ok(())
        },
        Err(error) => panic!("Error in event loop: {:?}", error),
    };
}

fn socket_event_loop(listener: TcpListener) -> Result<(), Box<std::error::Error>> {
    // Pick a token that will not be used by any other socket and use that one
    // for the listener.
    const LISTEN_TOKEN: Token = Token(5);
    const STDIN: Token = Token(0);

    // Used to store the client.
    let mut sockets = HashMap::new();

    // The `Poll` instance
    let poll = Poll::new()?;

    let context = "0.0.0.0";

    // Register the listener
    poll.register(&listener,
                LISTEN_TOKEN,
                Ready::readable(),
                PollOpt::edge())?;
    
    // Event storage
    let mut events = Events::with_capacity(1024);    

    let stdin_fd = io::stdin().as_raw_fd();
    poll.register(&EventedFd(&stdin_fd),
             STDIN, Ready::readable(), PollOpt::edge())?;
    //println!("{:?}", stdin);

    loop {
        // Wait for events
        poll.poll(&mut events, None)?;

        for event in &events {
            //println!("{:?}", event);
            match event.token() {
                LISTEN_TOKEN => {
                    // Perform operations in a loop until `WouldBlock` is
                    // encountered.
                    loop {
                        match listener.accept() {
                            Ok((mut socket, _)) => {
                                // Get the token for the socket
                                let new_client_token: Token = Token(socket.as_raw_fd() as usize);

                                // Register the new socket w/ poll
                                poll.register(&socket,
                                            new_client_token,
                                            Ready::readable(),
                                            PollOpt::edge())?;

                                let new_keys = match key_exchange(&socket) {
                                    Ok(keys) => keys,
                                    Err(error) => {
                                        println!("{:?}", error);
                                        break
                                    },
                                };
                                let mut client = Client {
                                        token: new_client_token,
                                        connection: socket,
                                        keys: new_keys
                                };

                                // Store the socket
                                sockets.insert(new_client_token, client);
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // Socket is not ready anymore, stop accepting
                                break;
                            }
                            // Unexpected error
                            error => panic!("Error: {:?}", error), 
                        }
                    }
                }
                STDIN => {
                    match input_loop(&sockets) {
                        Ok(_) => (),
                        Err(error) => {
                            if error == "exit" {
                                return Ok(());
                            }
                        }
                    };
                    
                    print!("{} >> ", context);
                    io::stdout().flush().unwrap();
                }
                token => {
                    // Always operate in a loop
                    match match_client(&sockets, token) {
                        Ok(_) => continue,
                        Err(error) => match error.kind() {
                            io::ErrorKind::BrokenPipe => {
                                /*
                                let client_ipv4 = match sockets.get(&token){
                                    Some(client) => client.connection.peer_addr().unwrap(),
                                    None => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                                };
                                println!("Removing client {:?} and {:?}", client_ipv4, token);
                                */
                                sockets.remove(&token);
                            },
                            error => panic!("Error: {:?}", error),
                        },
                    };
                }
            }
        }
    }
}

fn input_loop(sockets: &HashMap<mio::Token, Client>) -> Result<(), &str> {
    let mut rl = Editor::<()>::new();
    let builtin_commands = vec![
        String::from("help"),
        String::from("hosts"),
        String::from("quit"),
    ];

    let readline = rl.readline("");
    match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_ref());
            match &line[..] {
                "help" => {
                    println!("Available commands: {}", builtin_commands.join(", "));
                },
                "hosts" => {
                    if sockets.len() == 0 {
                        println!("No connected clients");
                        return Ok(());
                    }
                    for (token, client) in sockets {
                        println!("{}) {}", token.0, client.connection.peer_addr().unwrap());
                    }
                },
                "quit" => {
                    for (_, client) in sockets {
                        println!("Closing {}", client.connection.peer_addr().unwrap());
                        client.connection.shutdown(Shutdown::Both).unwrap();
                    }
                    return Err("exit")
                },
                _ => {
                    println!("{}", line);
                },
            }
        },
        Err(ReadlineError::Interrupted) => {
            println!("CTRL-C");
        },
        Err(ReadlineError::Eof) => {
            println!("CTRL-D");
        },
        Err(err) => {
            println!("Error: {:?}", err);
        },
    }

    Ok(())
}

/*
fn accept_client() {

}
*/

fn match_client(sockets: &HashMap<Token, Client>, token: mio::Token) -> Result<(), io::Error> {
    let custom_error = Error::new(ErrorKind::BrokenPipe, "Client disconnect");
    match sockets.get(&token).unwrap() {
        client => {
            let _c = match recv(&client.connection) {
                Ok(c) => c,
                Err(error) => match error.kind() {
                    io::ErrorKind::WouldBlock => {
                        // Socket is not ready anymore, stop reading
                        return Ok(());
                        //break;
                    },
                    io::ErrorKind::UnexpectedEof => {
                        //Client disconnect
                        return Result::Err(custom_error);
                        //break;
                    },
                    // Unexpected error
                    error => panic!("Error: {:?}", error), 
                },
            };
            //let m2 = aead::open(&c, None, &client.keys.nonce, &client.keys.rx).unwrap();
            //println!("Message: {}", String::from_utf8(m2).expect("Invalid utf-8"));
        },
    }

    Ok(())
}

fn key_exchange(connection: &TcpStream) -> Result<KeyMaterial, io::Error> {
    let nonce = aead::gen_nonce();
    let custom_error = Error::new(ErrorKind::BrokenPipe, "Client disconnect");
    let (server_pk, server_sk) = kx::gen_keypair();
    #[allow(unused_assignments)]
    let mut client_pk = vec![0u8; 65535];
    let five_seconds = Duration::new(5, 0);

    loop {
        client_pk = match recv(&connection) {
            Ok(client_pk) => {
                client_pk
            },
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock => {
                    // Socket is not ready anymore, stop reading
                    thread::sleep(five_seconds);
                    continue;
                },
                io::ErrorKind::UnexpectedEof => {
                    //Client disconnect
                    return Result::Err(custom_error);
                    //break;
                },
                // Unexpected error
                error => panic!("Error: {:?}", error), 
            },
        };
        break;
    }

    let client_pk = match sodiumoxide::crypto::kx::x25519blake2b::PublicKey::from_slice(&client_pk) {
        Some(v) => v,
        None => {
            panic!("Failed to convert client public key");
        },
    };
    println!("Received client public key: {:?}", client_pk);

    println!("Sending server public key: {:?}", server_pk.0);
    send(&connection, &server_pk.0)?;

    // server performs the same operation
    let (rx, tx) = match kx::server_session_keys(&server_pk, &server_sk, &client_pk) {
        Ok((rx, tx)) => (rx, tx),
        Err(()) => panic!("bad client signature"),
    };

    let key1 = match aead::Key::from_slice(&tx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    let key2 = match aead::Key::from_slice(&rx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    send(&connection, &nonce.0)?;

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
    //println!("{:?}", msg_len_buf);
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