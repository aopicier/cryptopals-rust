extern crate mac;
extern crate serialize;

extern crate hyper;
extern crate iron;
extern crate params;

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::{thread, time};

use iron::prelude::*;
use iron::status;
use params::Params;

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

fn file_hmac_sha1(key: &[u8], file: &str) -> Option<Vec<u8>> {
    let path = Path::new("/home/ph/Development/matasano/matasano/src/").join(file);

    let file = match File::open(&path) {
        Ok(file) => file,
        Err(_) => {
            println!("Failed to load file from {:?}", path);
            return None;
        }
    };
    let mut reader = BufReader::new(file);
    let mut content = Vec::new();
    reader.read_to_end(&mut content).ok().unwrap();
    Some(hmac_sha1(key, &content))
}

fn verify_signature(req: &mut Request, key: &[u8]) -> IronResult<Response> {
    let params = req.get_ref::<Params>().unwrap();
    let file = match params.find(&["file"]) {
        //None => return Err(CustomError::new("missing file parameter")),
        Some(&params::Value::String(ref file)) => file.clone(), // clone() is critical
        //_ => return Err(CustomError::new("file parameter was not a single string"))
        _ => return Ok(Response::with(status::InternalServerError)),
    };
    let signature = match params.find(&["signature"]) {
        //None => return Err(CustomError::new("missing signature parameter")),
        Some(&params::Value::String(ref signature)) => signature.clone(), // clone() is critical
        //_ => return Err(CustomError::new("signature parameter was not a single string"))
        _ => return Ok(Response::with(status::InternalServerError)),
    };

    let computed_hmac = match file_hmac_sha1(key, &file) {
        Some(hmac) => hmac,
        None => return Ok(Response::with(status::InternalServerError)),
    };

    if insecure_compare(&computed_hmac, &from_hex(&signature).unwrap()) {
        Ok(Response::with(status::Ok))
    } else {
        Ok(Response::with(status::InternalServerError))
    }
}

pub fn start(key: Vec<u8>) -> hyper::server::Listening {
    Iron::new(move |req: &mut Request| verify_signature(req, &key))
        .http("localhost:3000")
        .unwrap()
}
