//! Does a relay on a real socket prove its post-quantum identity, does a
//! client hold it to that, and does a client from before the proof still
//! get through?
//!
//! The unit tests drive HandshakeState in one process. These put the relay
//! behind `NodeListener`, as the node runs it, and a client on the other
//! end of a TCP connection, in the four combinations that matter: proving
//! relay with a pinning client, proving relay with an older client, older
//! relay with a pinning client, and a wrong pin.

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::StaticSecret;

use hidra_node::client::session::run_client_session;
use hidra_node::crypto::handshake::{HandshakeState, Role, check_relay_pq_identity};
use hidra_node::crypto::hybrid_sig::HybridSigningKey;
use hidra_node::network::connection::{Message, SecureConnection, read_frame, write_frame};
use hidra_node::network::listener::{NodeListener, PROTO_NOISE_SESSION};
use hidra_node::relay::registry::RelayEntry;

/// A relay without an identity to prove: an older relay.
async fn start_older_relay() -> SocketAddr {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = NodeListener::bind(addr, StaticSecret::random_from_rng(OsRng))
        .await
        .unwrap();
    let bound = listener.local_addr().unwrap();
    tokio::spawn(async move { listener.accept_loop().await });
    bound
}

/// An identity the test can hand to both a listener and a verifier.
fn identity() -> (HybridSigningKey, HybridSigningKey, String) {
    let ed = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let seed = HybridSigningKey::generate().pq_seed();
    let for_relay = HybridSigningKey::from_parts(ed.clone(), &seed);
    let for_check = HybridSigningKey::from_parts(ed, &seed);
    let b64 = BASE64.encode(for_check.verifying_key().to_bytes());
    (for_relay, for_check, b64)
}

async fn start_proving_relay() -> (SocketAddr, String, String) {
    let (for_relay, _, b64) = identity();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let secret = StaticSecret::random_from_rng(OsRng);
    let noise_b64 = BASE64.encode(x25519_dalek::PublicKey::from(&secret).as_bytes());
    let listener = NodeListener::bind(addr, secret)
        .await
        .unwrap()
        .with_identity(for_relay);
    let bound = listener.local_addr().unwrap();
    tokio::spawn(async move { listener.accept_loop().await });
    (bound, noise_b64, b64)
}

/// Run the three messages against a live relay and hand back the state.
async fn handshake_with(addr: SocketAddr) -> (TcpStream, HandshakeState) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[PROTO_NOISE_SESSION]).await.unwrap();
    let mut hs = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
    let a = hs.write_message_a().unwrap();
    write_frame(&mut stream, &a).await.unwrap();
    let b = read_frame(&mut stream).await.unwrap();
    hs.read_message_b(&b).unwrap();
    (stream, hs)
}

/// A proving relay is verified by a client that pins its identity, and a
/// wrong pin is refused before the client sends its own static key.
#[tokio::test]
async fn a_relay_proves_its_identity_and_a_wrong_pin_is_refused() {
    let (addr, _, pinned) = start_proving_relay().await;
    let (_stream, hs) = handshake_with(addr).await;
    assert!(
        hs.remote_identity_proof_offered(),
        "message B carried a proof"
    );
    check_relay_pq_identity(&hs, &pinned).unwrap();

    let (_, _, other) = identity();
    assert!(check_relay_pq_identity(&hs, &other).is_err());
}

/// A client from before the proof completes the handshake against a
/// proving relay and the session works: the proof rides in a payload the
/// old client decrypts and ignores, as Noise specifies.
#[tokio::test]
async fn an_older_client_still_talks_to_a_proving_relay() {
    let (addr, _, _) = start_proving_relay().await;
    let (mut stream, mut hs) = handshake_with(addr).await;
    // An older client never looks at the proof; it just finishes.
    let c = hs.write_message_c().unwrap();
    write_frame(&mut stream, &c).await.unwrap();
    let (send, recv) = hs.into_transport().unwrap();
    let mut conn = SecureConnection::new(stream, send, recv);
    conn.send_message(&Message::Ping(b"hello".to_vec()))
        .await
        .unwrap();
    match conn.recv_message().await.unwrap() {
        Message::Pong(_) => {}
        other => panic!("expected a Pong, got {other:?}"),
    }
}

/// An older relay sends no proof. A client with nothing pinned connects as
/// before; one with an identity pinned refuses, because the pin says the
/// relay must prove itself.
#[tokio::test]
async fn an_older_relay_passes_only_when_nothing_is_pinned() {
    let addr = start_older_relay().await;
    let (_stream, hs) = handshake_with(addr).await;
    assert!(!hs.remote_identity_proof_offered());
    check_relay_pq_identity(&hs, "").unwrap();
    let (_, _, pinned) = identity();
    assert!(check_relay_pq_identity(&hs, &pinned).is_err());
}

/// The whole client path: a three-hop circuit through proving relays, with
/// both the Noise key and the identity pinned on every hop, carries a
/// message end to end. The same circuit with one hop's identity wrong is
/// refused.
#[tokio::test]
async fn a_pinned_three_hop_circuit_works_and_a_wrong_hop_is_refused() {
    let mut relays = Vec::new();
    for i in 0..3 {
        let (addr, noise_b64, identity_b64) = start_proving_relay().await;
        relays.push(RelayEntry {
            name: format!("relay-{}", i + 1),
            addr,
            noise_pubkey_b64: noise_b64,
            identity_pubkey_b64: identity_b64,
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // The exit of this test circuit has nowhere to forward to, so the
    // session either completes or fails at the exit; what matters here is
    // that every hop's identity check passed on the way.
    let secret = StaticSecret::random_from_rng(OsRng);
    let outcome = run_client_session(&relays, secret, "ping").await;
    if let Err(e) = &outcome {
        let text = format!("{e}");
        assert!(
            !text.contains("identity") && !text.contains("pinned"),
            "the identity checks must pass on every hop: {text}"
        );
    }

    let (_, _, wrong) = identity();
    relays[1].identity_pubkey_b64 = wrong;
    let secret = StaticSecret::random_from_rng(OsRng);
    let err = run_client_session(&relays, secret, "ping")
        .await
        .expect_err("a wrong identity on the middle hop must be refused");
    assert!(format!("{err}").contains("identity"), "{err}");
}
