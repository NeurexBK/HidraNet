//! The relay's circuit table has edges, and the onion layers have their own
//! key without cutting off an older client.
//!
//! Three things a live relay must do: refuse a session that creates more
//! circuits than any client needs, forget a session's circuits when it ends,
//! and open a cell from a client that still encrypts the layers under the
//! transport key, as every client did before the layers got a key of their
//! own.

use std::net::SocketAddr;

use rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::StaticSecret;

use hidra_node::crypto::handshake::{HandshakeState, Role, onion_layer_key};
use hidra_node::crypto::hybrid_sig::HybridSigningKey;
use hidra_node::network::connection::{Message, SecureConnection, read_frame, write_frame};
use hidra_node::network::listener::{NodeListener, PROTO_FORWARDED_CELL, PROTO_NOISE_SESSION};
use hidra_node::onion::cell::LayerHeader;
use hidra_node::onion::layer::{peel_layer, wrap_layer};
use hidra_node::relay::router::MAX_CIRCUITS_PER_SESSION;

async fn start_proving_relay() -> SocketAddr {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = NodeListener::bind(addr, StaticSecret::random_from_rng(OsRng))
        .await
        .unwrap()
        .with_identity(HybridSigningKey::generate());
    let bound = listener.local_addr().unwrap();
    tokio::spawn(async move { listener.accept_loop().await });
    bound
}

/// A session with the relay: the transport key and the connection.
async fn open_session(addr: SocketAddr) -> (SecureConnection, [u8; 32], bool) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[PROTO_NOISE_SESSION]).await.unwrap();
    let mut hs = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
    let a = hs.write_message_a().unwrap();
    write_frame(&mut stream, &a).await.unwrap();
    let b = read_frame(&mut stream).await.unwrap();
    hs.read_message_b(&b).unwrap();
    let proven = hs.remote_identity_proof_offered();
    let c = hs.write_message_c().unwrap();
    write_frame(&mut stream, &c).await.unwrap();
    let (send, recv) = hs.into_transport().unwrap();
    let transport_key = send.session_key().unwrap();
    (
        SecureConnection::new(stream, send, recv),
        transport_key,
        proven,
    )
}

async fn create_circuit(conn: &mut SecureConnection, id: u32) -> bool {
    if conn
        .send_message(&Message::CreateCircuit { circuit_id: id })
        .await
        .is_err()
    {
        return false;
    }
    matches!(
        conn.recv_message().await,
        Ok(Message::CircuitCreated { circuit_id }) if circuit_id == id
    )
}

/// Send one legacy cell (no next hop, not a relay command) on the session
/// itself and return the exit's reply, peeled with `key`.
async fn exit_roundtrip(conn: &mut SecureConnection, id: u32, key: &[u8; 32]) -> Vec<u8> {
    let cell = wrap_layer(key, &LayerHeader { next_hop: None }, b"a legacy payload").unwrap();
    conn.send_message(&Message::Relay {
        circuit_id: id,
        data: cell,
    })
    .await
    .unwrap();
    match conn.recv_message().await.unwrap() {
        Message::Relay { data, .. } => peel_layer(key, &data).unwrap().1,
        other => panic!("expected a Relay reply, got {other:?}"),
    }
}

/// A forwarded cell for `id`, as the previous hop would send it. Returns the
/// peeled reply, or None when the relay closed without answering.
async fn forwarded_roundtrip(addr: SocketAddr, id: u32, key: &[u8; 32]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[PROTO_FORWARDED_CELL]).await.unwrap();
    let cell = wrap_layer(key, &LayerHeader { next_hop: None }, b"forwarded").unwrap();
    let msg = Message::Relay {
        circuit_id: id,
        data: cell,
    };
    write_frame(&mut stream, &msg.serialize()).await.unwrap();
    let frame = read_frame(&mut stream).await.ok()?;
    match Message::deserialize(&frame).ok()? {
        Message::Relay { data, .. } => Some(peel_layer(key, &data).unwrap().1),
        _ => None,
    }
}

/// A new client derives the layer key; an older client uses the transport
/// key. The same relay opens cells from both, learning which on the first.
#[tokio::test]
async fn the_relay_opens_cells_under_the_derived_key_and_the_legacy_key() {
    let addr = start_proving_relay().await;

    let (mut new_client, transport_key, proven) = open_session(addr).await;
    assert!(proven);
    assert!(create_circuit(&mut new_client, 1).await);
    let derived = onion_layer_key(&transport_key);
    assert_ne!(derived, transport_key);
    assert_eq!(
        exit_roundtrip(&mut new_client, 1, &derived).await,
        b"Received, agent"
    );

    let (mut old_client, transport_key, _) = open_session(addr).await;
    assert!(create_circuit(&mut old_client, 2).await);
    assert_eq!(
        exit_roundtrip(&mut old_client, 2, &transport_key).await,
        b"Received, agent",
        "a client from before the key split still gets through"
    );
}

/// A session may create only so many circuits; the one past the cap ends
/// the session rather than growing the table.
#[tokio::test]
async fn a_session_past_the_circuit_cap_is_closed() {
    let addr = start_proving_relay().await;
    let (mut conn, _, _) = open_session(addr).await;
    for id in 0..MAX_CIRCUITS_PER_SESSION as u32 {
        assert!(
            create_circuit(&mut conn, 1000 + id).await,
            "circuit {id} within the cap"
        );
    }
    assert!(
        !create_circuit(&mut conn, 5000).await,
        "the circuit past the cap must be refused"
    );
}

/// A circuit lives as long as the session that created it. While the session
/// is open, a forwarded cell for it is answered; once it closes, the circuit
/// is gone and the cell is not.
#[tokio::test]
async fn a_circuit_is_forgotten_when_its_session_ends() {
    let addr = start_proving_relay().await;
    let (mut conn, transport_key, _) = open_session(addr).await;
    assert!(create_circuit(&mut conn, 77).await);
    let key = onion_layer_key(&transport_key);

    assert_eq!(
        forwarded_roundtrip(addr, 77, &key).await.as_deref(),
        Some(&b"Received, agent"[..]),
        "a live circuit answers a forwarded cell"
    );

    drop(conn);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert!(
        forwarded_roundtrip(addr, 77, &key).await.is_none(),
        "a closed session's circuit must not be reachable any more"
    );
}
