use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::thread;

use diffie_hellman::client::Client;
use diffie_hellman::communication::Communicate;
use diffie_hellman::mitm::MITM;
use diffie_hellman::mitm::Mode;
use diffie_hellman::server::Server as DHServer;

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use rsa::Rsa;

use srp::server::Server as SrpServer;
use srp::client::Client as SrpClient;
use srp::client::FakeClientWithZeroKey as SrpFakeClient;

use errors::*;

fn handle_client<T: Communicate>(stream: T) -> Result<(), Error> {
    let mut server = DHServer::new(stream)?;

    while let Some(message) = server.receive()? {
        server.send(&message)?;
    }
    Ok(())
}

fn mitm_handle_client<T: Communicate>(client_stream: T, server_stream: T) -> Result<(), Error> {
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

fn run_tcp_server(port: u16) -> Result<thread::JoinHandle<Result<(), Error>>, Error> {
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((stream, _)) => handle_client(stream),
        Err(_) => bail!("connection failed"),
    }))
}

fn run_tcp_mitm(client_port: u16, server_port: u16) -> Result<thread::JoinHandle<Result<(), Error>>, Error> {
    let listener = TcpListener::bind(("localhost", client_port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((client_stream, _)) => {
            let server_stream = TcpStream::connect(("localhost", server_port))?;
            mitm_handle_client(client_stream, server_stream)
        }
        Err(_) => bail!("connection failed"),
    }))
}

fn matasano5_34() -> Result<(), Error> {
    matasano5_34_echo()?;
    matasano5_34_mitm()?;
    Ok(())
}

fn matasano5_34_echo() -> Result<(), Error> {
    let server_port: u16 = 8080;
    let client_port: u16 = 8080;
    let join_handle = run_tcp_server(server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port)).context("client failed to connect")?;

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

fn matasano5_34_mitm() -> Result<(), Error> {
    let server_port: u16 = 8080;
    let client_port: u16 = 8081;
    run_tcp_server(server_port)?;

    let join_handle = run_tcp_mitm(client_port, server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port)).context("client failed to connect")?;

    let mut client = Client::new(stream)?;
    // The message needs to match the hardcoded string in mitm_handle_client
    let message = b"This is a test";
    client.send(message)?;
    compare(Some(message.to_vec()), client.receive()?)?;

    client.stream().shutdown(Shutdown::Both)?;
    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn matasano5_35() -> Result<(), Error> {
    Err(ChallengeError::NotImplemented.into())
}

fn start_srp_tcp_server(port: u16) -> Result<(Sender<u8>, thread::JoinHandle<Result<(), Error>>), Error> {
    let mut server = SrpServer::new();
    let listener = TcpListener::bind(("localhost", port))?;
    let (tx, rx) = channel();
    let join_handle = thread::spawn(move || loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Check for shutdown signal
                if rx.try_recv().is_ok() {
                    return Ok(());
                }

                server.handle_client(&mut stream)?;
            }
            Err(_) => bail!("connection failed"),
        };
    });
    Ok((tx, join_handle))
}

fn shutdown_srp_tcp_server(port: u16, tx: Sender<u8>) -> Result<(), Error> {
    // Ugly hack for shutting down the server
    tx.send(1)?;

    let stream = TcpStream::connect(("localhost", port))
        .context("client failed to connect")?;

    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn connect_and_execute(port: u16, action: impl Fn(&mut TcpStream) ->  Result<(), Error>) -> Result<(), Error> {
    let mut stream = TcpStream::connect(("localhost", port))
        .context("client failed to connect")?;

    action(&mut stream)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn matasano5_36() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_srp_tcp_server(port)?;

    let user_name = b"foo";
    let password = b"baz";
    let client = SrpClient::new(user_name.to_vec(), password.to_vec());

    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    shutdown_srp_tcp_server(port, tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn matasano5_37() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_srp_tcp_server(port)?;

    let user_name = b"foo";
    let password = b"baz";

    let client = SrpClient::new(user_name.to_vec(), password.to_vec());
    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    let fake_client = SrpFakeClient::new(user_name.to_vec());
    connect_and_execute(port, |stream| fake_client.login(stream))?;

    shutdown_srp_tcp_server(port, tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn matasano5_38() -> Result<(), Error> {
    Err(ChallengeError::NotImplemented.into())
}

fn matasano5_39() -> Result<(), Error> {
    let rsa = Rsa::<BigNum>::generate(512);
    let m = BigNumTrait::from_u32(42);
    compare(&m, &rsa.decrypt(&rsa.encrypt(&m)))
}

fn matasano5_40() -> Result<(), Error> {
    let bits = 512;
    let m = BigNum::gen_random(bits - 1);
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
