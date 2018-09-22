use super::hmac_client;
use super::hmac_server;

use rand;
use rand::Rng;

use errors::*;

pub fn run() -> Result<(), Error> {
    println!("Challenge 32: takes about three minutes, pleases wait ...");
    let mut rng = rand::thread_rng();
    let key: Vec<u8> = rng.gen_iter().take(20).collect();

    let mut server = hmac_server::start(key)?;
    let result = hmac_client::run();
    server.close().context("failed to close connection")?;

    result
}
