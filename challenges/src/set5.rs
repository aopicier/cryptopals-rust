use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use diffie_hellman::client::Client;
use diffie_hellman::communication::Communicate;
use diffie_hellman::mitm::MITM;
use diffie_hellman::mitm::Mode;
use diffie_hellman::server::Server;

use bignum::BigNum;
use bignum::BigNumTrait;

use rsa::Rsa;

use errors::*;

fn handle_client<T: Communicate>(stream: T) -> Result<()> {
    let mut server = Server::new(stream)?;

    while let Some(message) = server.receive()? {
        server.send(&message)?;
    }
    Ok(())
}

fn mitm_handle_client<T: Communicate>(client_stream: T, server_stream: T) -> Result<()> {
    let mut mitm = MITM::new(client_stream, server_stream, Mode::PublicKey)?;
    loop {
        match mitm.receive_client()? {
            Some(message) => {
                compare(
                    mitm.decrypt_client(message.clone())?,
                    Some(b"This is a test".to_vec()),
                )?;
                mitm.send_server(&message);
            }
            None => break,
        }
        match mitm.receive_server()? {
            Some(message) => {
                compare(
                    mitm.decrypt_server(message.clone())?,
                    Some(b"This is a test".to_vec()),
                )?;
                mitm.send_client(&message);
            }
            None => break,
        }
    }
    Ok(())
}

fn run_tcp_server(port: u16) -> Result<thread::JoinHandle<Result<()>>> {
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((stream, _)) => handle_client(stream),
        Err(_) => bail!("connection failed"),
    }))
}

fn run_tcp_mitm(client_port: u16, server_port: u16) -> Result<thread::JoinHandle<Result<()>>> {
    let listener = TcpListener::bind(("localhost", client_port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((client_stream, _)) => {
            let server_stream = TcpStream::connect(("localhost", server_port))?;
            mitm_handle_client(client_stream, server_stream)
        }
        Err(_) => bail!("connection failed"),
    }))
}

fn matasano5_34() -> Result<()> {
    matasano5_34_echo()?;
    matasano5_34_mitm()?;
    Ok(())
}

fn matasano5_34_echo() -> Result<()> {
    let server_port: u16 = 8080;
    let client_port: u16 = 8080;
    let join_handle = run_tcp_server(server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port)).chain_err(|| "client failed to connect")?;

    let mut client = Client::new(stream)?;
    let message = b"This is a test";
    client.send(message)?;
    compare(Some(message.to_vec()), client.receive()?)?;

    client.stream().shutdown(Shutdown::Both)?;
    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn matasano5_34_mitm() -> Result<()> {
    let server_port: u16 = 8080;
    let client_port: u16 = 8081;
    run_tcp_server(server_port)?;

    let join_handle = run_tcp_mitm(client_port, server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port)).chain_err(|| "client failed to connect")?;

    let mut client = Client::new(stream)?;
    let message = b"This is a test"; //This needs to match the hardcoded string in mitm_handle_client
    client.send(message)?;
    compare(Some(message.to_vec()), client.receive()?)?;

    client.stream().shutdown(Shutdown::Both)?;
    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn matasano5_35() -> Result<()> {
    bail!(ErrorKind::NotImplemented);
}

fn matasano5_36() -> Result<()> {
    bail!(ErrorKind::NotImplemented);
}

fn matasano5_37() -> Result<()> {
    bail!(ErrorKind::NotImplemented);
}

fn matasano5_38() -> Result<()> {
    bail!(ErrorKind::NotImplemented);
}

fn matasano5_39() -> Result<()> {
    let rsa = Rsa::<BigNum>::generate(512);
    let m = BigNumTrait::from_u32(42);
    compare(&m, &rsa.decrypt(&rsa.encrypt(&m)))
}

fn matasano5_40() -> Result<()> {
    let bits = 512;
    let m = <BigNum as BigNumTrait>::gen_random(bits - 1);
    let rsa1 = Rsa::generate(bits);
    let rsa2 = Rsa::generate(bits);
    let rsa3 = Rsa::generate(bits);
    let c1 = rsa1.encrypt(&m);
    let c2 = rsa2.encrypt(&m);
    let c3 = rsa3.encrypt(&m);
    let n1 = rsa1.n();
    let n2 = rsa2.n();
    let n3 = rsa3.n();
    let x1 = n2 * n3;
    let x2 = n1 * n3;
    let x3 = n1 * n2;
    /* Let N = n1*n2*n3. The following formula is based on the inverse function
     * IZ/(n1) x IZ(n2) x IZ(n3) -> IZ/(N)
     * from the Chinese Remainder Theorem. Of course this only works when n1, n2 and n3 don't have
     * any common divisors.
     *
     * We also use the following fact: As the public exponent of our encryption is hardcoded to 3,
     * we have m^3 = ci mod ni, hence also m^3 = c mod N. As m < min(n1, n2, n3), we have m^3 < N.
     * By definition, we also have c < N. Combining these statements we obtain m^3 = c in IZ (!),
     * so that we can recover m as the third root in IZ of c, which is easy to obtain. */

    let c = &(&(&(&(&c1 * &x1) * &x1.invmod(n1).unwrap())
        + &(&(&c2 * &x2) * &x2.invmod(n2).unwrap()))
        + &(&(&c3 * &x3) * &x3.invmod(n3).unwrap())) % &(&(n1 * n2) * n3);
    compare(&m, &c.root(3).0)
}

pub fn run() {
    println!("Set 5");
    run_exercise(matasano5_34, 34);
    run_exercise(matasano5_35, 35);
    run_exercise(matasano5_36, 36);
    run_exercise(matasano5_37, 37);
    run_exercise(matasano5_38, 38);
    run_exercise(matasano5_39, 39);
    run_exercise(matasano5_40, 40);
}
