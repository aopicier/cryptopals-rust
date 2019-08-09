use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use diffie_hellman::communication::Communicate;
use diffie_hellman::handshake::{
    ClientDeterminesParameters, ClientServerPair, Handshake, ServerCanOverrideParameters,
};
use diffie_hellman::mitm_handshake::{
    MitmFakeGeneratorOne, MitmFakeGeneratorP, MitmFakeGeneratorPMinusOne, MitmFakePublicKey,
    MitmForClientServer, MitmHandshake,
};
use diffie_hellman::mitm_session::MitmSession;
use diffie_hellman::session::Session;

use crate::errors::*;

fn handle_client<S: Handshake<TcpStream>>(stream: TcpStream) -> Result<()> {
    let mut server = Session::new::<S>(stream)?;
    while let Some(message) = server.receive()? {
        server.send(&message)?;
    }
    Ok(())
}

struct InterceptedMessages {
    decrypted_client_messages: Vec<Vec<u8>>,
    decrypted_server_messages: Vec<Vec<u8>>,
}

fn mitm_handle_client<M: MitmHandshake<TcpStream>>(
    client_stream: TcpStream,
    server_stream: TcpStream,
) -> Result<InterceptedMessages> {
    let mut mitm = MitmSession::new::<M>(client_stream, server_stream)?;
    let mut decrypted_client_messages = Vec::new();
    let mut decrypted_server_messages = Vec::new();
    loop {
        match mitm.receive_client()? {
            Some(message) => {
                if let Some(decrypted_message) = mitm.decrypt_client(&message)? {
                    decrypted_client_messages.push(decrypted_message);
                }

                mitm.send_server(&message)?;
            }
            None => break,
        }
        match mitm.receive_server()? {
            Some(message) => {
                if let Some(decrypted_message) = mitm.decrypt_server(&message)? {
                    decrypted_server_messages.push(decrypted_message);
                }
                mitm.send_client(&message)?;
            }
            None => break,
        }
    }
    mitm.server_stream().shutdown(Shutdown::Both)?;
    Ok(InterceptedMessages {
        decrypted_client_messages,
        decrypted_server_messages,
    })
}

fn start_server<S: Handshake<TcpStream>>(port: u16) -> Result<thread::JoinHandle<Result<()>>> {
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((stream, _)) => handle_client::<S>(stream),
        Err(_) => Err(ConnectionFailed.into()),
    }))
}

fn start_mitm<M: MitmHandshake<TcpStream>>(
    client_port: u16,
    server_port: u16,
) -> Result<thread::JoinHandle<Result<InterceptedMessages>>> {
    let listener = TcpListener::bind(("localhost", client_port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((client_stream, _)) => {
            let server_stream = TcpStream::connect(("localhost", server_port))?;
            mitm_handle_client::<M>(client_stream, server_stream)
        }
        Err(_) => Err(ConnectionFailed.into()),
    }))
}

fn run_echo<P: ClientServerPair<TcpStream>>() -> Result<()> {
    let server_port: u16 = 8080;
    let client_port: u16 = 8080;
    let message = b"This is a test";

    let join_handle = start_server::<P::Server>(server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port))/*.context("client failed to connect")*/?;

    let mut client = Session::new::<P::Client>(stream)?;

    client.send(message)?;
    compare_eq(Some(message.to_vec()), client.receive()?)?;

    client.stream().shutdown(Shutdown::Both)?;
    match join_handle.join() {
        Ok(result) => result,
        _ => Err("tcp listener thread panicked".into()),
    }
}

fn run_mitm<T: MitmForClientServer<TcpStream>>() -> Result<()>
where
    T::Mitm: 'static + Send,
{
    let server_port: u16 = 8080;
    let client_port: u16 = 8081;
    let message = b"This is a test".to_vec();

    let jh_server = start_server::<<T::CS as ClientServerPair<TcpStream>>::Server>(server_port)?;

    let jh_mitm = start_mitm::<T::Mitm>(client_port, server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port))/*.context("client failed to connect")*/?;

    let mut client = Session::new::<<T::CS as ClientServerPair<TcpStream>>::Client>(stream)?;
    client.send(&message)?;
    compare_eq(Some(&message), client.receive()?.as_ref())/*.context("message received by client")*/?;

    client.stream().shutdown(Shutdown::Both)?;

    match jh_server.join() {
        Ok(result) => result/*.context("server error")*/?,
        _ => return Err("tcp listener thread panicked".into()),
    };

    match jh_mitm.join() {
        Ok(result) => {
            let InterceptedMessages {
                decrypted_client_messages,
                decrypted_server_messages,
            } = result?;
            compare_eq(1, decrypted_client_messages.len())/*.context("number of client messages")*/?;
            compare_eq(1, decrypted_server_messages.len())/*.context("number of server messages")*/?;
            compare_eq(&message, &decrypted_client_messages[0])
                /*.context("decrypted client message")*/?;
            compare_eq(&message, &decrypted_server_messages[0])
                /*.context("decrypted server message")*/?;
            Ok(())
        }
        _ => Err("tcp listener thread panicked".into()),
    }
}

pub fn run34() -> Result<()> {
    run_echo::<ClientDeterminesParameters>()?;
    run_mitm::<MitmFakePublicKey>()?;
    Ok(())
}

pub fn run35() -> Result<()> {
    run_echo::<ServerCanOverrideParameters>()?;
    run_mitm::<MitmFakeGeneratorOne>()?;
    run_mitm::<MitmFakeGeneratorP>()?;
    run_mitm::<MitmFakeGeneratorPMinusOne>()?;
    Ok(())
}
