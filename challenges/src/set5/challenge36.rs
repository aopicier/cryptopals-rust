use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::thread;

use srp::client::Client as SrpClient;
use srp::mitm::Mitm as SrpSimplifiedMitm;
use srp::mitm::PasswordOracle as MitmPasswordOracle;
use srp::server::ClientHandler;
use srp::server::Server as SrpServer;

use errors::*;

#[cfg_attr(feature = "cargo-clippy", allow(type_complexity))]
pub fn start_srp_listener<T: ClientHandler>(
    mut server: T,
    port: u16,
) -> Result<(Sender<u8>, thread::JoinHandle<Result<(), Error>>), Error> {
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
            Err(_) => bail!("connection failed"),
        };
    });
    Ok((tx, join_handle))
}

pub fn start_mitm_srp_server(
    port: u16,
) -> Result<thread::JoinHandle<Result<MitmPasswordOracle, Error>>, Error> {
    let mitm = SrpSimplifiedMitm::new();
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((mut stream, _)) => Ok(mitm.handle_client(&mut stream)?),
        Err(_) => bail!("connection failed"),
    }))
}

pub fn shutdown_srp_server(port: u16, tx: &Sender<u8>) -> Result<(), Error> {
    // Ugly hack for shutting down the server
    tx.send(1)?;

    let stream = TcpStream::connect(("localhost", port)).context("client failed to connect")?;

    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

pub fn connect_and_execute(
    port: u16,
    action: impl Fn(&mut TcpStream) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut stream = TcpStream::connect(("localhost", port)).context("client failed to connect")?;

    action(&mut stream)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

pub fn run() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_srp_listener(SrpServer::new(), port)?;

    let user_name = b"foo";
    let password = b"baz";
    let client = SrpClient::new(user_name.to_vec(), password.to_vec());

    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    shutdown_srp_server(port, &tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

