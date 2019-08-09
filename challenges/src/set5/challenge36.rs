use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::thread;

use srp::client::Client;
use srp::server::ClientHandler;
use srp::server::Server;

use crate::errors::*;

#[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
pub fn start_server<T: ClientHandler>(
    mut server: T,
    port: u16,
) -> Result<(Sender<u8>, thread::JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(("localhost", port))?;
    let (tx, rx) = channel();
    let join_handle = thread::spawn(move || loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Check for shutdown signal
                if rx.try_recv().is_ok() {
                    return Ok(());
                }

                server.handle_client(&mut stream)?;
            }
            Err(_) => return Err(ConnectionFailed.into()),
        };
    });
    Ok((tx, join_handle))
}

pub fn shutdown_server(port: u16, tx: &Sender<u8>) -> Result<()> {
    // Ugly hack for shutting down the server
    tx.send(1)?;

    let stream = TcpStream::connect(("localhost", port))/*.context("client failed to connect")*/?;

    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

pub fn connect_and_execute(port: u16, action: impl Fn(&mut TcpStream) -> Result<()>) -> Result<()> {
    let mut stream =
        TcpStream::connect(("localhost", port))/*.context("client failed to connect")*/?;

    action(&mut stream)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

pub fn run() -> Result<()> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_server(Server::default(), port)?;

    let user_name = b"foo";
    let password = b"baz";
    let client = Client::new(user_name.to_vec(), password.to_vec());

    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    shutdown_server(port, &tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => Err("tcp listener thread panicked".into()),
    }
}
