use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::time;

use crate::errors::*;
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

fn try_signature(client: &Client, body: &HashMap<&str, String>) -> Result<bool> {
    let request = client.post("http://localhost:3000").json(&body);

    let response = request.json(&body).send()?;

    Ok(response.status() == StatusCode::OK)
}

fn perform_measurement(
    client: &Client,
    body: &HashMap<&str, String>,
    n: u32,
) -> Result<(f32, f32)> {
    let measurements = (0..n)
        .map(|_| {
            let now = time::Instant::now();
            try_signature(client, body)?;
            let elapsed_time = now.elapsed();
            let elapsed_micros = (elapsed_time.as_secs() as f32) * 1_000_000.0
                + (elapsed_time.subsec_nanos() as f32) / 1_000.0;
            Ok(elapsed_micros)
        })
        .collect::<Result<Vec<f32>>>()?;

    let mu = mean(&measurements);
    let sd = squared_deviation(&measurements, mu);
    Ok((mu, sd))
}

pub fn run() -> Result<()> {
    let client = Client::new();
    let mut body = HashMap::new();
    body.insert("file", "4.txt".to_string());

    let mut mac = vec![0; 20];

    // Number of measurements to perform per signature
    let n = 3;

    for i in 0..mac.len() {
        let mut u_max = 0;
        let mut stat_max = (0f32, 0f32);
        for u in 0..=255 {
            mac[i] = u;

            body.insert("signature", mac.to_hex());
            let stat = perform_measurement(&client, &body, n)?;

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

    body.insert("signature", mac.to_hex());
    if !try_signature(&client, &body)? {
        return Err("Failed to determine mac.".into());
    }

    Ok(())
}
