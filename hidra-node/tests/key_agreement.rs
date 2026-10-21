//! A client and a relay agree on a hop's keys over a real socket, and a relay
//! cell sealed with them opens at the relay and nowhere else.

use hidra_node::crypto::circuit_handshake::{respond, Initiator};
use hidra_node::network::connection::{read_frame, write_frame};
use hidra_node::onion::layer::{ClientHop, ClientLayers, Peeled, RelayHop};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test]
async fn session_keys_match_and_layer_roundtrips() {
    let relay_secret = StaticSecret::random_from_rng(OsRng);
    let relay_key = PublicKey::from(&relay_secret);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let relay_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let a = read_frame(&mut stream).await.unwrap();
        let (b, keys) = respond(&relay_secret, &a).unwrap();
        write_frame(&mut stream, &b).await.unwrap();
        let cell = read_frame(&mut stream).await.unwrap();
        let mut hop = RelayHop::new(keys);
        let Peeled::Here(body) = hop.peel(&cell).unwrap() else {
            panic!("a one-hop cell is for the hop")
        };
        let reply = hop.originate(&body).unwrap();
        write_frame(&mut stream, &reply).await.unwrap();
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (init, a) = Initiator::start(&relay_key).unwrap();
    write_frame(&mut stream, &a).await.unwrap();
    let b = read_frame(&mut stream).await.unwrap();
    let mut layers = ClientLayers::new();
    layers.push(ClientHop::new(init.finish(&b).unwrap()));

    let cell = layers.seal(0, b"test payload").unwrap();
    assert!(!cell.windows(12).any(|w| w == b"test payload"));
    write_frame(&mut stream, &cell).await.unwrap();
    let reply = read_frame(&mut stream).await.unwrap();
    assert_eq!(layers.open(&reply).unwrap(), (0, b"test payload".to_vec()));

    relay_task.await.unwrap();
}
