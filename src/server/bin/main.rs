extern crate sodiumoxide;
extern crate mio;
extern crate rustyline;
extern crate serde;
extern crate uuid;

use std::io::{self, Read, Write, Error, ErrorKind};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, Shutdown};
use std::time::{Duration};
use std::{thread};
use std::os::unix::io::AsRawFd;

use sodiumoxide::crypto::kx::*;
use sodiumoxide::crypto::secretbox::*;

use mio::{Events, Ready, Poll, PollOpt, Token};
use mio::net::{TcpStream, TcpListener};
use mio::unix::EventedFd;

use rustyline::error::ReadlineError;
use rustyline::config::Builder;
use rustyline::Editor;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
struct Client {
    token: mio::Token,
    connection: TcpStream,
    remote_address: SocketAddr,
    agent_uuid: uuid::Uuid,
    keys: AgentConfiguration,
}

#[derive(Serialize, Deserialize, Debug)]
struct AgentConfiguration {
    rx: Key,
    tx: Key,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyExchange {
    client_public_key: PublicKey,
    agent_uuid: uuid::Uuid,    
}

#[macro_export]
macro_rules! some_or_continue {
  ($option:expr) => {
    match $option {
      Some(value) => value,
      None => continue,
    }
  }
}

#[macro_export]
macro_rules! ok_or_continue {
  ($result:expr) => {
    match $result {
      Ok(value) => value,
      Err(_e) => continue /* do something with that error? */,
    }
  }
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
    print!("{} >> ", context);
    io::stdout().flush().unwrap();

    let rustyline_config_builder = Builder::new().max_history_size(1024).auto_add_history(true);
    let rustyline_config = rustyline_config_builder.build();
    let mut readline_editor = Editor::<>::with_config(rustyline_config);

    loop {
        // Wait for events
        poll.poll(&mut events, None)?;

        for event in &events {
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

                                let (new_keys, new_agent_uuid) = match key_exchange(&socket) {
                                    Ok(keys) => keys,
                                    Err(error) => {
                                        println!("{:?}", error);
                                        break
                                    },
                                };

                                let new_client_address = socket.try_clone().unwrap().peer_addr().unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
                                let mut client = Client {
                                        token: new_client_token,
                                        connection: socket,
                                        remote_address: new_client_address,
                                        agent_uuid: new_agent_uuid,
                                        keys: new_keys
                                };
                                println!("New agent connected: {} - {}", client.remote_address, client.agent_uuid);

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
                    match input_loop(&sockets, &mut readline_editor) {
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
                                {
                                    let client = some_or_continue!(sockets.get(&token));
                                    println!("Client disconnect: {} - {}", client.remote_address, client.agent_uuid);
                                }
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

fn input_loop<'a>(sockets: &HashMap<mio::Token, Client>, readline_editor: &mut rustyline::Editor<()>) -> Result<(), &'a str> {
    let builtin_commands = vec![
        String::from("help"),
        String::from("hosts"),
        String::from("disconnect"),
        String::from("quit"),
    ];

    let readline = readline_editor.readline("");
    match readline {
        Ok(line) => {
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
                        println!("{}) {} - {}", token.0, client.remote_address, client.agent_uuid);
                    }
                },
                line if line.starts_with("disconnect") => {
                    let mut clients_to_disconnect: Vec<mio::Token> = Vec::with_capacity(1024);
                    for client_token in line.trim_start_matches("disconnect").split_whitespace() {
                        clients_to_disconnect.push(Token(ok_or_continue!(client_token.parse::<usize>())));
                    }

                    for client_token in clients_to_disconnect {
                        let client = some_or_continue!(sockets.get(&client_token));
                        ok_or_continue!(client.connection.shutdown(Shutdown::Both));
                        println!("Disconnecting client {}: {}", client.token.0, client.remote_address);
                    }

                }
                "quit" => {
                    for (_, client) in sockets {
                        println!("Closing {}", client.remote_address);
                        ok_or_continue!(client.connection.shutdown(Shutdown::Both));
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
            //let m2 = open(&c, &client.keys.nonce, &client.keys.rx).unwrap();
            //println!("Message: {}", String::from_utf8(m2).expect("Invalid utf-8"));
        },
    }

    Ok(())
}

fn key_exchange(connection: &TcpStream) -> Result<(AgentConfiguration, uuid::Uuid), Error> {
    let nonce = gen_nonce();
    let custom_error = Error::new(ErrorKind::BrokenPipe, "Client disconnect");
    let (server_public_key, server_private_key) = gen_keypair();
    #[allow(unused_assignments)]
    let mut client_public_key = vec![0u8; 65535];
    let five_seconds = Duration::new(5, 0);

    loop {
        client_public_key = match recv(&connection) {
            Ok(client_public_key) => {
                client_public_key
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

    let client_initial_info: KeyExchange = serde_json::from_slice(&client_public_key)?;
    send(&connection, &server_public_key.0)?;

    // server performs the same operation
    let (rx, tx) = match server_session_keys(&server_public_key, &server_private_key, &client_initial_info.client_public_key) {
        Ok((rx, tx)) => (rx, tx),
        Err(()) => panic!("bad client signature"),
    };

    let key1 = match Key::from_slice(&tx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    let key2: Key = match Key::from_slice(&rx.0) {
        Some(v) => v,
        None => {
            panic!("Failed to convert to aead key");
        }
    };

    send(&connection, &nonce.0)?;

    Ok((AgentConfiguration {
        tx: key1,
        rx: key2,
        nonce: nonce,
    }, client_initial_info.agent_uuid))
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