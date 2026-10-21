//! What a circuit refuses, end to end against real relays.
//!
//! - The links between relays carry nothing in the clear. Version 1 sent each
//!   forwarded cell as a plain frame — the cell type and the circuit id in the
//!   open — to anyone on the path, and accepted a cell from anyone who
//!   connected.
//! - A cell sent twice does not open twice. Version 1 opened it again, and the
//!   exit would repeat a request to its destination.
//! - A circuit id that exists cannot be registered again. Version 1 replaced
//!   the circuit's key, so anyone who knew the id could break the circuit.
//! - A peer still speaking version 1 is refused at the first byte.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::crypto::handshake::{HandshakeState, Role};
use hidra_node::network::connection::{read_frame, write_frame, Message, SecureConnection};
use hidra_node::network::listener::{NodeListener, PROTO_NOISE_SESSION, PROTO_RELAY_LINK};
use hidra_node::onion::cell::LayerHeader;
use hidra_node::onion::layer::LayerCipher;
use hidra_node::relay::exit_policy::ExitPolicy;
use hidra_node::relay::registry::RelayEntry;

async fn start_relay() -> (SocketAddr, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let key = BASE64.encode(PublicKey::from(&secret).to_bytes());
    let listener = NodeListener::bind("127.0.0.1:0".parse().unwrap(), secret)
        .await
        .unwrap()
        .with_exit_policy(ExitPolicy::ALLOW_PRIVATE);
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { listener.accept_loop().await });
    (addr, key)
}

/// Every connection that passed the tap: its first byte and everything sent
/// towards the relay.
#[derive(Clone, Default)]
struct Tap(Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>);

impl Tap {
    fn connections(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().iter().map(|c| c.lock().unwrap().clone()).collect()
    }
}

/// A transparent relay in front of `node` that records what is sent to it.
async fn tap_in_front_of(node: SocketAddr) -> (SocketAddr, Tap) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tap = Tap::default();
    let tap_for_task = tap.clone();
    tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            let seen = Arc::new(Mutex::new(Vec::new()));
            tap_for_task.0.lock().unwrap().push(Arc::clone(&seen));
            tokio::spawn(async move {
                let Ok(outbound) = TcpStream::connect(node).await else { return };
                let (mut in_rd, mut in_wr) = inbound.into_split();
                let (mut out_rd, mut out_wr) = outbound.into_split();
                let up = async {
                    let mut buf = vec![0u8; 16384];
                    loop {
                        match in_rd.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                seen.lock().unwrap().extend_from_slice(&buf[..n]);
                                if out_wr.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = out_wr.shutdown().await;
                };
                let down = async {
                    let _ = tokio::io::copy(&mut out_rd, &mut in_wr).await;
                    let _ = in_wr.shutdown().await;
                };
                tokio::join!(up, down);
            });
        }
    });
    (addr, tap)
}

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// A client session with one relay, by hand: the Noise handshake and the
/// layer built from its key, as the client does for its guard.
async fn session(relay: SocketAddr) -> (SecureConnection, LayerCipher) {
    let mut stream = TcpStream::connect(relay).await.unwrap();
    stream.write_all(&[PROTO_NOISE_SESSION]).await.unwrap();
    let mut hs = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
    write_frame(&mut stream, &hs.write_message_a().unwrap()).await.unwrap();
    let b = read_frame(&mut stream).await.unwrap();
    hs.read_message_b(&b).unwrap();
    write_frame(&mut stream, &hs.write_message_c().unwrap()).await.unwrap();
    let (send, recv) = hs.into_transport().unwrap();
    let layer = LayerCipher::new(&send.session_key().unwrap());
    (SecureConnection::new(stream, send, recv), layer)
}

/// The relay's next message, or None once it has closed the link.
async fn next_message(conn: &mut SecureConnection) -> Option<Message> {
    match tokio::time::timeout(Duration::from_secs(5), conn.recv_message()).await {
        Ok(Ok(m)) => Some(m),
        Ok(Err(_)) => None,
        Err(_) => panic!("the relay neither answered nor closed the link"),
    }
}

#[tokio::test]
async fn links_between_relays_carry_nothing_in_the_clear() {
    let (guard, guard_key) = start_relay().await;
    let (middle, middle_key) = start_relay().await;
    let (exit, exit_key) = start_relay().await;
    let (t_middle, tap_middle) = tap_in_front_of(middle).await;
    let (t_exit, tap_exit) = tap_in_front_of(exit).await;
    let echo = start_echo_server().await;

    let relays = vec![
        RelayEntry { name: "guard".into(), addr: guard, noise_pubkey_b64: guard_key },
        RelayEntry { name: "middle".into(), addr: t_middle, noise_pubkey_b64: middle_key },
        RelayEntry { name: "exit".into(), addr: t_exit, noise_pubkey_b64: exit_key },
    ];
    let mut circuit = StreamingCircuit::build(&relays, StaticSecret::random_from_rng(OsRng))
        .await
        .unwrap();
    let id = circuit.circuit_id().to_be_bytes();
    circuit.connect(&echo.ip().to_string(), echo.port()).await.unwrap();
    for _ in 0..3 {
        circuit.send_data(b"through the circuit").await.unwrap();
        assert_eq!(circuit.recv_data().await.unwrap().unwrap(), b"through the circuit");
    }
    circuit.send_end().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    for (name, tap) in [("middle", &tap_middle), ("exit", &tap_exit)] {
        let conns = tap.connections();
        let links: Vec<&Vec<u8>> = conns.iter().filter(|c| c.first() == Some(&PROTO_RELAY_LINK)).collect();
        assert!(!links.is_empty(), "the {name} was never reached over a relay link");
        assert!(
            conns.iter().all(|c| c.first() != Some(&0x01)),
            "something reached the {name} over a version 1 link"
        );
        for link in links {
            // A version 1 frame: the Relay (0x20) or StreamBegin (0x21) tag,
            // then the circuit id, in the clear.
            let in_clear = link
                .windows(5)
                .any(|w| (w[0] == 0x20 || w[0] == 0x21) && w[1..] == id);
            assert!(!in_clear, "the circuit id crossed the link to the {name} in the clear");
        }
    }
}

#[tokio::test]
async fn a_cell_sent_twice_closes_the_link_instead_of_opening_twice() {
    let (relay, _) = start_relay().await;
    let (mut conn, mut layer) = session(relay).await;
    let id = 0x5eed_0001;
    conn.send_message(&Message::CreateCircuit { circuit_id: id }).await.unwrap();
    assert_eq!(next_message(&mut conn).await, Some(Message::CircuitCreated { circuit_id: id }));

    let cell = layer.seal_forward_cell(&LayerHeader { next_hop: None }, b"once").unwrap();
    conn.send_message(&Message::Relay { circuit_id: id, data: cell.clone() }).await.unwrap();
    match next_message(&mut conn).await {
        Some(Message::Relay { data, .. }) => {
            assert_eq!(layer.open_backward(&data).unwrap(), b"Received, agent");
        }
        other => panic!("expected the relay's reply, got {other:?}"),
    }

    conn.send_message(&Message::Relay { circuit_id: id, data: cell }).await.unwrap();
    assert_eq!(next_message(&mut conn).await, None, "the relay opened the same cell a second time");
}

#[tokio::test]
async fn a_circuit_id_in_use_cannot_be_taken_over() {
    let (relay, _) = start_relay().await;
    let id = 0x5eed_0002;
    let (mut owner, mut layer) = session(relay).await;
    owner.send_message(&Message::CreateCircuit { circuit_id: id }).await.unwrap();
    assert_eq!(next_message(&mut owner).await, Some(Message::CircuitCreated { circuit_id: id }));

    let (mut intruder, _) = session(relay).await;
    intruder.send_message(&Message::CreateCircuit { circuit_id: id }).await.unwrap();
    assert_eq!(next_message(&mut intruder).await, None, "a second session registered an id in use");

    // The owner's circuit still opens under the owner's layer.
    let cell = layer.seal_forward_cell(&LayerHeader { next_hop: None }, b"still mine").unwrap();
    owner.send_message(&Message::Relay { circuit_id: id, data: cell }).await.unwrap();
    match next_message(&mut owner).await {
        Some(Message::Relay { data, .. }) => {
            assert_eq!(layer.open_backward(&data).unwrap(), b"Received, agent");
        }
        other => panic!("the owner's circuit stopped working: {other:?}"),
    }
}

#[tokio::test]
async fn a_peer_speaking_version_1_is_refused() {
    let (relay, _) = start_relay().await;
    for old in [0x00u8, 0x01] {
        let mut stream = TcpStream::connect(relay).await.unwrap();
        stream.write_all(&[old]).await.unwrap();
        // What a version 1 relay link sent: a Relay frame in the clear.
        let _ = write_frame(&mut stream, &Message::Relay { circuit_id: 7, data: vec![0; 40] }.serialize()).await;
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the relay kept a version 1 connection open")
            .unwrap_or(0);
        assert_eq!(n, 0, "the relay answered a version 1 peer (first byte {old:#04x})");
    }
}
