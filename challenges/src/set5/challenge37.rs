use srp::client::Client as SrpClient;
use srp::client::FakeClientWithZeroKey as SrpFakeClient;
use srp::server::Server as SrpServer;

use errors::*;

use super::challenge36::{start_srp_listener, shutdown_srp_server, connect_and_execute};

pub fn run() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_srp_listener(SrpServer::new(), port)?;

    let user_name = b"foo";
    let password = b"baz";

    let client = SrpClient::new(user_name.to_vec(), password.to_vec());
    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    let fake_client = SrpFakeClient::new(user_name.to_vec());
    connect_and_execute(port, |stream| fake_client.login(stream))?;

    shutdown_srp_server(port, &tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

