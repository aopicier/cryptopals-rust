#[macro_use]
extern crate failure;
extern crate hyper;
extern crate serialize;

use failure::Error;
use hyper::client::Client;
use hyper::header::ContentType;
use std::time;

use serialize::Serialize;

fn mean(u: &[f32]) -> f32 {
    let n = u.len() as f32;
    u.iter().fold(0f32, |a, b| a + b) / n
}

fn squared_deviation(u: &[f32], mu: f32) -> f32 {
    u.iter().fold(0f32, |a, b| a + (b - mu).powi(2))
}

fn t_statistic(n: f32, (mu_u, sd_u): (f32, f32), (mu_v, sd_v): (f32, f32)) -> f32 {
    let m = n;
    let var = (sd_u + sd_v) / (n + m - 2f32);
    (n * m / (n + m)).sqrt() * (mu_u - mu_v) / var.sqrt()
}

fn try_signature(mac: &[u8]) -> Result<bool, Error> {
    let client = Client::new();
    let mime = "application/json".parse().unwrap();
    let body = format!("{{\"file\":\"4.txt\", \"signature\":\"{}\"}}", mac.to_hex());

    let request = client
        .post("http://localhost:3000")
        .header(ContentType(mime))
        .body(&body);

    let response = request.send()?;

    Ok(response.status == hyper::status::StatusCode::Ok)
}

fn perform_measurement(mac: &[u8], n: u32) -> Result<(f32, f32), Error> {
    let measurements = (0..n)
        .map(|_| {
            let now = time::Instant::now();
            try_signature(mac)?;
            let elapsed_time = now.elapsed();
            let elapsed_micros = (elapsed_time.as_secs() as f32) * 1_000_000.0
                + (elapsed_time.subsec_nanos() as f32) / 1_000.0;
            Ok(elapsed_micros)
        }).collect::<Result<Vec<f32>, Error>>()?;

    let mu = mean(&measurements);
    let sd = squared_deviation(&measurements, mu);
    Ok((mu, sd))
}

pub fn run() -> Result<(), Error> {
    let mut mac = vec![0; 20];

    // Number of measurements to perform per signature
    let n = 3;

    for i in 0..mac.len() {
        let mut u_max = 0;
        let mut stat_max = (0f32, 0f32);
        for u in 0..=255 {
            mac[i] = u;
            let stat = perform_measurement(&mac, n)?;

            // Two-sample t-test to test whether the mean in stat is bigger than the mean in
            // stat_max.
            let t = t_statistic(n as f32, stat_max, stat);
            if t < -2f32 {
                u_max = u;
                stat_max = stat;
            }
        }
        mac[i] = u_max;
    }

    if !try_signature(&mac)? {
        bail!("Failed to determine mac");
    }

    Ok(())
}
