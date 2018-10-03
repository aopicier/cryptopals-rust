use srp::client::Client;
use srp::client::FakeClientWithZeroKey;
use srp::server::Server;

use crate::errors::*;

use super::challenge36::{connect_and_execute, shutdown_server, start_server};

pub fn run() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_server(Server::default(), port)?;

    let user_name = b"foo";
    let password = b"baz";

    let client = Client::new(user_name.to_vec(), password.to_vec());
    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    let attacker = FakeClientWithZeroKey::new(user_name.to_vec());
    connect_and_execute(port, |stream| attacker.login(stream))?;

    shutdown_server(port, &tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}
