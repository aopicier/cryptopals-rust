extern crate hyper;
extern crate serialize;
extern crate unstable_features;

use std::time;
use hyper::client::Client;
use hyper::header::ContentType;

use unstable_features::all_bytes;
use serialize::Serialize;

fn mean(u: &[f32]) -> f32 {
    let n = u.len() as f32;
    u.iter().fold(0f32, |a, b| a+b)/n
}

fn variance(u: &[f32], mu: f32) -> f32 {
    u.iter().fold(0f32, |a, b| a+(b-mu).powi(2))
}

fn t_statistic(n: f32, (mu_u, var_u): (f32, f32), (mu_v, var_v): (f32, f32)) -> f32 {
    let m = n;
    let var = (var_u + var_v)/(n + m - 2f32);
    (n*m/(n+m)).sqrt()*(mu_u - mu_v)/var.sqrt()
}

fn try_signature(mac: &[u8]) -> (bool, f32) {
    let client = Client::new();
    let mime = "application/json".parse().unwrap();
    let body = format!("{{\"file\":\"4.txt\", \"signature\":\"{}\"}}", mac.to_hex());
    let request = client.post("http://localhost:3000")
        .header(ContentType(mime))
        .body(&body);
    let now = time::Instant::now();
    let response = request.send().unwrap();
    let elapsed_time = now.elapsed();
    let elapsed_micros = (elapsed_time.as_secs() as f32)*1_000_000.0 + (elapsed_time.subsec_nanos() as f32)/1_000.0;
    (response.status == hyper::status::StatusCode::Ok, elapsed_micros)
}

fn perform_measurement(mac: &[u8], n: u32) -> (f32, f32) {
    let measurements: Vec<f32> = (0..n).map(|_| try_signature(mac).1).collect();
    let mu = mean(&measurements);
    let var = variance(&measurements, mu);
    (mu, var)
}

pub fn run() {
    let mut mac = vec![0; 20];
    let n = 3;
    for i in 0..mac.len() {
        let mut u_max = 0;
        let mut stat_max = (0f32, 0f32);
        for u in all_bytes() {
            mac[i] = u;
            let stat = perform_measurement(&mac, n);
            let t = t_statistic(n as f32, stat_max, stat);
            if  t < -2f32  {
                u_max = u;
                stat_max = stat;
            }
        }
        mac[i] = u_max;
    }
    assert!(try_signature(&mac).0);
}
