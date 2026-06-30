use hidra_node::crypto::handshake::{HandshakeState, Role};
use hidra_node::network::connection::{read_frame, write_frame};
use hidra_node::onion::cell::LayerHeader;
use hidra_node::onion::layer::{wrap_layer, peel_layer};
use rand_core::OsRng;
use x25519_dalek::StaticSecret;

#[tokio::test]
async fn session_keys_match_and_layer_roundtrips() {
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let relay_secret = StaticSecret::random_from_rng(OsRng);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let relay_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hs = HandshakeState::new(Role::Responder, relay_secret);

        let a = read_frame(&mut stream).await.unwrap();
        hs.read_message_a(&a).unwrap();
        let b = hs.write_message_b().unwrap();
        write_frame(&mut stream, &b).await.unwrap();
        let c = read_frame(&mut stream).await.unwrap();
        hs.read_message_c(&c).unwrap();

        let (send_cipher, recv_cipher) = hs.into_transport().unwrap();
        let relay_recv_key = recv_cipher.session_key().unwrap();
        let relay_send_key = send_cipher.session_key().unwrap();
        (relay_recv_key, relay_send_key)
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut hs = HandshakeState::new(Role::Initiator, client_secret);

    let a = hs.write_message_a().unwrap();
    write_frame(&mut stream, &a).await.unwrap();
    let b = read_frame(&mut stream).await.unwrap();
    hs.read_message_b(&b).unwrap();
    let c = hs.write_message_c().unwrap();
    write_frame(&mut stream, &c).await.unwrap();

    let (send_cipher, recv_cipher) = hs.into_transport().unwrap();
    let client_send_key = send_cipher.session_key().unwrap();
    let client_recv_key = recv_cipher.session_key().unwrap();

    let (relay_recv_key, relay_send_key) = relay_task.await.unwrap();

    // Verify key agreement
    assert_eq!(client_send_key, relay_recv_key, "client send = relay recv");
    assert_eq!(client_recv_key, relay_send_key, "client recv = relay send");

    // Verify wrap/peel with the agreed key
    let header = LayerHeader { next_hop: None };
    let encrypted = wrap_layer(&client_send_key, &header, b"test payload").unwrap();
    let (h, peeled) = peel_layer(&relay_recv_key, &encrypted).unwrap();
    assert!(h.next_hop.is_none());
    assert_eq!(peeled, b"test payload");
}
