use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::{thread, time};

use iron::prelude::*;
use iron::status;
use params::{Params, Value};

use crate::errors::*;
use mac::hmac_sha1;
use serialize::from_hex;

fn insecure_compare(u: &[u8], v: &[u8]) -> bool {
    if u.len() != v.len() {
        return false;
    }

    for (x, y) in u.iter().zip(v.iter()) {
        if x != y {
            return false;
        }
        thread::sleep(time::Duration::from_millis(1));
    }
    true
}

fn compute_hmac(key: &[u8], file: &str) -> Option<Vec<u8>> {
    let path = Path::new("data/").join(file);

    let file = File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    let mut content = Vec::new();
    reader.read_to_end(&mut content).ok().unwrap();
    Some(hmac_sha1(key, &content))
}

fn parse_body<'a>(req: &'a mut Request) -> Option<(&'a str, &'a str)> {
    let params = req.get_ref::<Params>().ok()?;

    let file = match params.find(&["file"]) {
        Some(&Value::String(ref file)) => file,
        _ => return None,
    };

    let signature = match params.find(&["signature"]) {
        Some(&Value::String(ref signature)) => signature,
        _ => return None,
    };

    Some((file, signature))
}

fn verify_signature(file: &str, signature: &str, key: &[u8]) -> Option<bool> {
    let computed_hmac = compute_hmac(key, &file)?;
    Some(insecure_compare(
        &computed_hmac,
        &from_hex(&signature).ok()?,
    ))
}

fn handle_request(req: &mut Request, key: &[u8]) -> IronResult<Response> {
    if let Some((file, signature)) = parse_body(req) {
        if verify_signature(file, signature, key) == Some(true) {
            return Ok(Response::with(status::Ok));
        }
    }

    Ok(Response::with(status::InternalServerError))
}

pub fn start(key: Vec<u8>) -> Result<iron::Listening> {
    Iron::new(move |req: &mut Request| handle_request(req, &key))
        .http("localhost:3000")
        .map_err(|err| err.into())
}
