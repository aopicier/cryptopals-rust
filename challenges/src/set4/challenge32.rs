use hmac_client;
use hmac_server;

use rand;
use rand::Rng;

use errors::*;

pub fn run() -> Result<(), Error> {
    let skip_exercise = true;

    if skip_exercise {
        return Err(ChallengeError::Skipped("Runs very long.").into());
    }

    let mut rng = rand::thread_rng();
    let key: Vec<u8> = rng.gen_iter().take(20).collect();

    let mut server = hmac_server::start(key)?;
    let result = hmac_client::run();
    server.close().context("failed to close connection")?;

    result
}
