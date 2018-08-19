use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::thread;

use rand;
use rand::Rng;

use diffie_hellman::communication::Communicate;
use diffie_hellman::mitm_session::MitmSession;
use diffie_hellman::mitm_handshake::{MitmHandshake, MitmFakePublicKey, MitmForClientServer, MitmFakeGeneratorOne, MitmFakeGeneratorP, MitmFakeGeneratorPMinusOne};
use diffie_hellman::session::Session;
use diffie_hellman::handshake::{ClientServerPair, ClientDeterminesParameters, ServerCanOverrideParameters, Handshake};

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use rsa::Rsa;

use srp::client::Client as SrpClient;
use srp::client::FakeClientWithZeroKey as SrpFakeClient;
use srp::client::SimplifiedClient as SrpSimplifiedClient;
use srp::mitm::Mitm as SrpSimplifiedMitm;
use srp::mitm::PasswordOracle as MitmPasswordOracle;
use srp::server::ClientHandler;
use srp::server::Server as SrpServer;
use srp::server::SimplifiedServer as SrpSimplifiedServer;

use errors::*;

fn handle_client<S: Handshake<TcpStream>>(stream: TcpStream) -> Result<(), Error> {
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

fn mitm_handle_client<M: MitmHandshake<TcpStream>>(client_stream: TcpStream, server_stream: TcpStream) -> Result<InterceptedMessages, Error> {
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
    Ok(InterceptedMessages { decrypted_client_messages, decrypted_server_messages })
}

fn run_dh_server<S: Handshake<TcpStream>>(port: u16) -> Result<thread::JoinHandle<Result<(), Error>>, Error> {
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((stream, _)) => handle_client::<S>(stream),
        Err(_) => bail!("connection failed"),
    }))
}

fn run_dh_mitm<M: MitmHandshake<TcpStream>>(
    client_port: u16,
    server_port: u16,
) -> Result<thread::JoinHandle<Result<InterceptedMessages, Error>>, Error> {
    let listener = TcpListener::bind(("localhost", client_port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((client_stream, _)) => {
            let server_stream = TcpStream::connect(("localhost", server_port))?;
            mitm_handle_client::<M>(client_stream, server_stream)
        }
        Err(_) => bail!("connection failed"),
    }))
}

fn challenge_33() -> Result<(), Error> {
    // See diffie_hellman crate
    Ok(())
}

fn challenge_34() -> Result<(), Error> {
    challenge_34_35_echo::<ClientDeterminesParameters>()?;
    challenge_34_35_mitm::<MitmFakePublicKey>()?;
    Ok(())
}

fn challenge_35() -> Result<(), Error> {
    challenge_34_35_echo::<ServerCanOverrideParameters>()?;
    challenge_34_35_mitm::<MitmFakeGeneratorOne>()?;
    challenge_34_35_mitm::<MitmFakeGeneratorP>()?;
    challenge_34_35_mitm::<MitmFakeGeneratorPMinusOne>()?;
    Ok(())
}

fn challenge_34_35_echo<P: ClientServerPair<TcpStream>>() -> Result<(), Error> {
    let server_port: u16 = 8080;
    let client_port: u16 = 8080;
    let message = b"This is a test";

    let join_handle = 
        run_dh_server::<P::Server>(server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port)).context("client failed to connect")?;

    let mut client = Session::new::<P::Client>(stream)?;

    client.send(message)?;
    compare_eq(Some(message.to_vec()), client.receive()?)?;

    client.stream().shutdown(Shutdown::Both)?;
    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn challenge_34_35_mitm<Trio: MitmForClientServer<TcpStream>>() -> Result<(), Error> 
where Trio::Mitm: 'static + Send {
    let server_port: u16 = 8080;
    let client_port: u16 = 8081;
    let message = b"This is a test".to_vec();

    let jh_server = 
        run_dh_server::<<Trio::CS as ClientServerPair<TcpStream>>::Server>(server_port)?;

    let jh_mitm = 
        run_dh_mitm::<Trio::Mitm>(client_port, server_port)?;

    let stream =
        TcpStream::connect(("localhost", client_port)).context("client failed to connect")?;

    let mut client = Session::new::<<Trio::CS as ClientServerPair<TcpStream>>::Client>(stream)?;
    client.send(&message)?;
    compare_eq(Some(&message), client.receive()?.as_ref()).context("message received by client")?;

    client.stream().shutdown(Shutdown::Both)?;

    match jh_server.join() {
        Ok(result) => result.context("server error")?,
        _ => bail!("tcp listener thread panicked"),
    };

    match jh_mitm.join() {
        Ok(result) => {
            let InterceptedMessages {decrypted_client_messages, decrypted_server_messages } = result?;
            compare_eq(1, decrypted_client_messages.len()).context("number of client messages")?;
            compare_eq(1, decrypted_server_messages.len()).context("number of client messages")?;
            compare_eq(&message, &decrypted_client_messages[0]).context("decrypted client message")?;
            compare_eq(&message, &decrypted_server_messages[0]).context("decrypted server message")?;
            Ok(())
        },
        _ => bail!("tcp listener thread panicked"),
    }
}

fn start_srp_listener<T: ClientHandler>(
    mut server: T,
    port: u16,
) -> Result<(Sender<u8>, thread::JoinHandle<Result<(), Error>>), Error> {
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

fn start_mitm_srp_server(
    port: u16,
) -> Result<thread::JoinHandle<Result<MitmPasswordOracle, Error>>, Error> {
    let mitm = SrpSimplifiedMitm::new();
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(thread::spawn(move || match listener.accept() {
        Ok((mut stream, _)) => Ok(mitm.handle_client(&mut stream)?),
        Err(_) => bail!("connection failed"),
    }))
}

fn shutdown_srp_server(port: u16, tx: Sender<u8>) -> Result<(), Error> {
    // Ugly hack for shutting down the server
    tx.send(1)?;

    let stream = TcpStream::connect(("localhost", port)).context("client failed to connect")?;

    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn connect_and_execute(
    port: u16,
    action: impl Fn(&mut TcpStream) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut stream = TcpStream::connect(("localhost", port)).context("client failed to connect")?;

    action(&mut stream)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn challenge_36() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_srp_listener(SrpServer::new(), port)?;

    let user_name = b"foo";
    let password = b"baz";
    let client = SrpClient::new(user_name.to_vec(), password.to_vec());

    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    shutdown_srp_server(port, tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn challenge_37() -> Result<(), Error> {
    let port: u16 = 8080;
    let (tx, join_handle) = start_srp_listener(SrpServer::new(), port)?;

    let user_name = b"foo";
    let password = b"baz";

    let client = SrpClient::new(user_name.to_vec(), password.to_vec());
    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    let fake_client = SrpFakeClient::new(user_name.to_vec());
    connect_and_execute(port, |stream| fake_client.login(stream))?;

    shutdown_srp_server(port, tx)?;

    match join_handle.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn challenge_38() -> Result<(), Error> {
    // Dictionary of the 25 most popular passwords
    let dictionary = &[
        b"123456".to_vec(),
        b"password".to_vec(),
        b"12345678".to_vec(),
        b"qwerty".to_vec(),
        b"12345".to_vec(),
        b"123456789".to_vec(),
        b"letmein".to_vec(),
        b"1234567".to_vec(),
        b"football".to_vec(),
        b"iloveyou".to_vec(),
        b"admin".to_vec(),
        b"welcome".to_vec(),
        b"monkey".to_vec(),
        b"login".to_vec(),
        b"abc123".to_vec(),
        b"starwars".to_vec(),
        b"123123".to_vec(),
        b"dragon".to_vec(),
        b"passw0rd".to_vec(),
        b"master".to_vec(),
        b"hello".to_vec(),
        b"freedom".to_vec(),
        b"whatever".to_vec(),
        b"qazwsx".to_vec(),
        b"trustno1".to_vec(),
    ];

    let port: u16 = 8080;
    let port_mitm: u16 = 8081;
    let (tx, jh_server) = start_srp_listener(SrpSimplifiedServer::new(), port)?;

    let user_name = b"foo";
    let client = create_client_with_random_password(user_name, dictionary);

    // Register with the server and make sure we can log in
    connect_and_execute(port, |stream| client.register(stream))?;
    connect_and_execute(port, |stream| client.login(stream))?;

    let jh_mitm = start_mitm_srp_server(port_mitm)?;

    // Accidentally connect with the MITM server
    connect_and_execute(port_mitm, |stream| client.login(stream))?;

    let password_oracle = jh_mitm
        .join()
        .map_err(|_| err_msg("tcp listener thread panicked"))??;

    // Dictionary attack against the password
    let password = dictionary
        .iter()
        .find(|pw| password_oracle.is_password(pw))
        .ok_or_else(|| err_msg("could not determine password"))?;

    let impostor = SrpSimplifiedClient::new(user_name.to_vec(), password.to_vec());
    connect_and_execute(port, |stream| impostor.login(stream))
        .context("impostor did not succeed")?;

    shutdown_srp_server(port, tx)?;

    match jh_server.join() {
        Ok(result) => result,
        _ => bail!("tcp listener thread panicked"),
    }
}

fn create_client_with_random_password(
    user_name: &[u8],
    dictionary: &[Vec<u8>],
) -> SrpSimplifiedClient {
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0, dictionary.len());
    let password = &dictionary[index];
    SrpSimplifiedClient::new(user_name.to_vec(), password.to_vec())
}

fn challenge_39() -> Result<(), Error> {
    let rsa = Rsa::<BigNum>::generate(512);
    let m = BigNumTrait::from_u32(42);
    compare_eq(&m, &rsa.decrypt(&rsa.encrypt(&m)))
}

fn challenge_40() -> Result<(), Error> {
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
        + &(&(&c3 * &x3) * &x3.invmod(n3).unwrap()))
        % &(&(n1 * n2) * n3);
    compare_eq(&m, &c.root(3).0)
}

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge_33);
    challenges.push(challenge_34);
    challenges.push(challenge_35);
    challenges.push(challenge_36);
    challenges.push(challenge_37);
    challenges.push(challenge_38);
    challenges.push(challenge_39);
    challenges.push(challenge_40);
}
