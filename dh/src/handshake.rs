use crate::algo::DH;
use crate::communication::Communicate;
use bignum::NumBigInt as BigNum;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub trait Handshake<T: Communicate> {
    fn handshake(stream: &mut T) -> Result<Vec<u8>>;
}

pub trait ClientServerPair<T: Communicate> {
    type Client: Handshake<T>;
    type Server: Handshake<T>;
}

// Client-Server pair used for challenge 34

pub struct ServerHandshake;

impl<T: Communicate> Handshake<T> for ServerHandshake {
    #[allow(non_snake_case)]
    fn handshake(stream: &mut T) -> Result<Vec<u8>> {
        let p = stream.receive()?.ok_or_else(|| "did not receive p")?;
        let g = stream.receive()?.ok_or_else(|| "did not receive g")?;
        let dh = DH::<BigNum>::new_with_parameters(&p, &g);
        let B = dh.public_key();
        stream.send(&B)?;
        let A = stream.receive()?.ok_or_else(|| "did not receive A")?;
        Ok(dh.shared_key(&A))
    }
}

pub struct ClientHandshake;

impl<T: Communicate> Handshake<T> for ClientHandshake {
    #[allow(non_snake_case)]
    fn handshake(stream: &mut T) -> Result<Vec<u8>> {
        let dh = DH::<BigNum>::new();
        let (p, g) = dh.parameters();
        stream.send(&p)?;
        stream.send(&g)?;
        let A = dh.public_key();
        stream.send(&A)?;
        let B = stream.receive()?.ok_or_else(|| "did not receive B")?;
        Ok(dh.shared_key(&B))
    }
}

pub struct ClientDeterminesParameters;

impl<T: Communicate> ClientServerPair<T> for ClientDeterminesParameters {
    type Client = ClientHandshake;
    type Server = ServerHandshake;
}

// Client-Server pair used for challenge 35

pub struct ServerHandshakeAck;

impl<T: Communicate> Handshake<T> for ServerHandshakeAck {
    #[allow(non_snake_case)]
    fn handshake(stream: &mut T) -> Result<Vec<u8>> {
        let p = stream.receive()?.ok_or_else(|| "did not receive p")?;
        let g = stream.receive()?.ok_or_else(|| "did not receive g")?;
        stream.send(&p)?;
        stream.send(&g)?;
        let dh = DH::<BigNum>::new_with_parameters(&p, &g);
        let B = dh.public_key();
        stream.send(&B)?;
        let A = stream.receive()?.ok_or_else(|| "did not receive A")?;

        Ok(dh.shared_key(&A))
    }
}

pub struct ClientHandshakeAck;

impl<T: Communicate> Handshake<T> for ClientHandshakeAck {
    #[allow(non_snake_case)]
    fn handshake(stream: &mut T) -> Result<Vec<u8>> {
        {
            let dh = DH::<BigNum>::new();
            let (p, g) = dh.parameters();
            stream.send(&p)?;
            stream.send(&g)?;
        }
        let p = stream.receive()?.ok_or_else(|| "did not receive p")?;
        let g = stream.receive()?.ok_or_else(|| "did not receive g")?;
        let dh = DH::<BigNum>::new_with_parameters(&p, &g);
        let A = dh.public_key();
        stream.send(&A)?;
        let B = stream.receive()?.ok_or_else(|| "did not receive B")?;

        Ok(dh.shared_key(&B))
    }
}

pub struct ServerCanOverrideParameters;

impl<T: Communicate> ClientServerPair<T> for ServerCanOverrideParameters {
    type Client = ClientHandshakeAck;
    type Server = ServerHandshakeAck;
}
