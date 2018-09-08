use rand;
use rand::Rng;

use srp::client::SimplifiedClient as SrpSimplifiedClient;
use srp::server::SimplifiedServer as SrpSimplifiedServer;

use super::challenge36::{
    connect_and_execute, shutdown_srp_server, start_mitm_srp_server, start_srp_listener,
};

use errors::*;

fn create_client_with_random_password(
    user_name: &[u8],
    dictionary: &[Vec<u8>],
) -> SrpSimplifiedClient {
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0, dictionary.len());
    let password = &dictionary[index];
    SrpSimplifiedClient::new(user_name.to_vec(), password.to_vec())
}

pub fn run() -> Result<(), Error> {
    // Dictionary of the 25 most popular passwords
    let dictionary = &[
        b"123456".to_vec(),
        b"password".to_vec(),
        b"12345678".to_vec(),
        b"qwerty".to_vec(),
        b"12345".to_vec(),
        b"123456789".to_vec(),
        b"letmein".to_vec(),
        b"1234567".to_vec(),
        b"football".to_vec(),
        b"iloveyou".to_vec(),
        b"admin".to_vec(),
        b"welcome".to_vec(),
        b"monkey".to_vec(),
        b"login".to_vec(),
        b"abc123".to_vec(),
        b"starwars".to_vec(),
        b"123123".to_vec(),
        b"dragon".to_vec(),
        b"passw0rd".to_vec(),
        b"master".to_vec(),
        b"hello".to_vec(),
        b"freedom".to_vec(),
        b"whatever".to_vec(),
        b"qazwsx".to_vec(),
        b"trustno1".to_vec(),
    ];

    let port: u16 = 8080;
    let port_mitm: u16 = 8081;
    let (tx, jh_server) = start_srp_listener(SrpSimplifiedServer::new(), port)?;

    let user_name = b"foo";
    let client = create_client_with_random_password(user_name, dictionary);

    // Register with the server and make sure we can log in
    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    let jh_mitm = start_mitm_srp_server(port_mitm)?;

    // Accidentally connect with the MITM server
    connect_and_execute(port_mitm, |stream| client.login(stream))?;

    let password_oracle = jh_mitm
        .join()
        .map_err(|_| err_msg("tcp listener thread panicked"))??;

    // Dictionary attack against the password
    let password = dictionary
        .iter()
        .find(|pw| password_oracle.is_password(pw))
        .ok_or_else(|| err_msg("could not determine password"))?;

    let impostor = SrpSimplifiedClient::new(user_name.to_vec(), password.to_vec());
    connect_and_execute(port, |stream| impostor.login(stream))
        .context("impostor did not succeed")?;

    shutdown_srp_server(port, &tx)?;

    match jh_server.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}
