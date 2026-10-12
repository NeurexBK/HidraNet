use base64::Engine as _;
use hidra_node::client::{session::run_client_session, streaming::StreamingCircuit};
use hidra_node::crypto::handshake::{HandshakeState, Role};
use hidra_node::network::connection::{read_frame, write_frame};
use hidra_node::network::listener::{NodeListener, PROTO_NOISE_SESSION};
use hidra_node::relay::registry::RelayEntry;
use rand_core::OsRng;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey, StaticSecret};

async fn relays(pinned: bool) -> Vec<RelayEntry> {
    let mut entries = Vec::new();
    for i in 0..3 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret);
        let listener = NodeListener::bind("127.0.0.1:0".parse().unwrap(), secret)
            .await
            .unwrap();
        entries.push(RelayEntry {
            name: format!("relay-{i}"),
            addr: listener.local_addr().unwrap(),
            noise_pubkey_b64: if pinned {
                base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
            } else {
                String::new()
            },
        });
        tokio::spawn(async move { listener.accept_loop().await });
    }
    entries
}

#[tokio::test]
async fn matching_pins_work_in_both_client_paths() {
    let entries = relays(true).await;
    StreamingCircuit::build(&entries, StaticSecret::random_from_rng(OsRng))
        .await
        .unwrap();
    assert_eq!(
        run_client_session(&entries, StaticSecret::random_from_rng(OsRng), "sample")
            .await
            .unwrap(),
        "Received, agent"
    );
}

#[tokio::test]
async fn empty_pins_preserve_unpinned_discovery() {
    let entries = relays(false).await;
    StreamingCircuit::build(&entries, StaticSecret::random_from_rng(OsRng))
        .await
        .unwrap();
    run_client_session(&entries, StaticSecret::random_from_rng(OsRng), "sample")
        .await
        .unwrap();
}

#[tokio::test]
async fn mismatched_pins_fail_in_both_client_paths() {
    let mut entries = relays(true).await;
    entries[0].noise_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let streaming = StreamingCircuit::build(&entries, StaticSecret::random_from_rng(OsRng))
        .await
        .err()
        .expect("the wrong relay key must be rejected");
    let session = run_client_session(&entries, StaticSecret::random_from_rng(OsRng), "sample")
        .await
        .unwrap_err();
    for error in [streaming, session] {
        assert!(
            error
                .to_string()
                .contains("does not match configured identity"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn a_mismatched_pin_stops_before_sending_client_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entry = RelayEntry {
        name: "wrong-identity".into(),
        addr: listener.local_addr().unwrap(),
        noise_pubkey_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
    };
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), PROTO_NOISE_SESSION);
        let mut handshake =
            HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        handshake
            .read_message_a(&read_frame(&mut stream).await.unwrap())
            .unwrap();
        write_frame(&mut stream, &handshake.write_message_b().unwrap())
            .await
            .unwrap();
        assert!(
            read_frame(&mut stream).await.is_err(),
            "client identity must not be sent to a mismatched relay"
        );
    });
    assert!(
        StreamingCircuit::build(&vec![entry; 3], StaticSecret::random_from_rng(OsRng))
            .await
            .is_err()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn malformed_pins_are_rejected_before_connecting() {
    for pin in [
        "not-base64".to_string(),
        base64::engine::general_purpose::STANDARD.encode([0u8; 31]),
    ] {
        // No server is required: malformed configuration must fail before TCP.
        let entry = RelayEntry {
            name: "malformed".into(),
            addr: "127.0.0.1:1".parse().unwrap(),
            noise_pubkey_b64: pin,
        };
        let error = StreamingCircuit::build(
            &vec![entry.clone(); 3],
            StaticSecret::random_from_rng(OsRng),
        )
        .await
        .err()
        .expect("malformed pins must fail");
        assert!(error.to_string().contains("relay public key"), "{error}");
        let error = run_client_session(
            &vec![entry; 3],
            StaticSecret::random_from_rng(OsRng),
            "sample",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("relay public key"), "{error}");
    }
}
