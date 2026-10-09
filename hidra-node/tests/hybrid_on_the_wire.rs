//! Does a real connection between two nodes actually carry the ML-KEM
//! exchange, and does the traffic stop if it is interfered with?
//!
//! The unit tests drive HandshakeState directly. This one puts a TCP socket in
//! the middle and reads the bytes, because the question that mattered here was
//! never "is the code correct" — it was "is the code reached".

use std::time::Duration;

use hidra_node::crypto::handshake::{HandshakeState, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::StaticSecret;

const DH_LEN: usize = 32;
const KEM_EK_LEN: usize = 1568;
const KEM_CT_LEN: usize = 1568;
const TAG_LEN: usize = 16;

async fn write_frame(s: &mut TcpStream, data: &[u8]) {
    s.write_all(&(data.len() as u32).to_be_bytes()).await.unwrap();
    s.write_all(data).await.unwrap();
    s.flush().await.unwrap();
}

async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.unwrap();
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).await.unwrap();
    buf
}

/// Runs a full handshake over a socket and hands back the three messages.
async fn exchange() -> (Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut hs = HandshakeState::new(
            Role::Responder,
            StaticSecret::random_from_rng(rand_core::OsRng),
        );
        let a = read_frame(&mut socket).await;
        hs.read_message_a(&a).unwrap();
        let b = hs.write_message_b().unwrap();
        write_frame(&mut socket, &b).await;
        let c = read_frame(&mut socket).await;
        hs.read_message_c(&c).unwrap();
        let (send, _) = hs.into_transport().unwrap();
        (a, b, c, send.session_key().unwrap())
    });

    let mut socket = TcpStream::connect(addr).await.unwrap();
    let mut hs = HandshakeState::new(
        Role::Initiator,
        StaticSecret::random_from_rng(rand_core::OsRng),
    );
    let a = hs.write_message_a().unwrap();
    write_frame(&mut socket, &a).await;
    let b = read_frame(&mut socket).await;
    hs.read_message_b(&b).unwrap();
    let c = hs.write_message_c().unwrap();
    write_frame(&mut socket, &c).await;
    let (_, recv) = hs.into_transport().unwrap();

    let (ra, rb, rc, r_key) = responder.await.unwrap();
    assert_eq!(a, ra);
    assert_eq!(b, rb);
    assert_eq!(c, rc);
    (a, b, c, recv.session_key().unwrap(), r_key)
}

#[tokio::test]
async fn a_real_connection_carries_the_ml_kem_exchange() {
    let (a, b, _c, i_key, r_key) = exchange().await;

    assert_eq!(
        a.len(),
        DH_LEN + KEM_EK_LEN,
        "message A must put an ML-KEM encapsulation key on the wire"
    );
    assert_eq!(
        b.len(),
        DH_LEN + KEM_CT_LEN + TAG_LEN + DH_LEN + TAG_LEN + TAG_LEN,
        "message B must put an ML-KEM ciphertext on the wire"
    );
    assert_eq!(i_key, r_key, "both ends derive the same session key");
}

/// An attacker on the path who rewrites the ML-KEM ciphertext does not get a
/// working session — implicit rejection makes the chaining keys diverge and
/// the next tag fails.
#[tokio::test]
async fn rewriting_the_ml_kem_ciphertext_kills_the_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut hs = HandshakeState::new(
            Role::Responder,
            StaticSecret::random_from_rng(rand_core::OsRng),
        );
        let a = read_frame(&mut socket).await;
        hs.read_message_a(&a).unwrap();
        let mut b = hs.write_message_b().unwrap();
        b[DH_LEN + 8] ^= 0x01; // one bit, inside the encrypted ciphertext
        write_frame(&mut socket, &b).await;
    });

    let mut socket = TcpStream::connect(addr).await.unwrap();
    let mut hs = HandshakeState::new(
        Role::Initiator,
        StaticSecret::random_from_rng(rand_core::OsRng),
    );
    write_frame(&mut socket, &hs.write_message_a().unwrap()).await;
    let b = read_frame(&mut socket).await;
    assert!(
        hs.read_message_b(&b).is_err(),
        "a rewritten ML-KEM ciphertext must not produce a session"
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), responder).await;
}
