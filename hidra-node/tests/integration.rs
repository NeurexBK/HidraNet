use hidra_node::crypto::handshake::{HandshakeState, Role};
use hidra_node::network::connection::{read_frame, write_frame, Message, SecureConnection};
use rand_core::OsRng;
use x25519_dalek::StaticSecret;

#[tokio::test]
async fn two_nodes_handshake_and_ping_pong() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Responder (node B)
    let responder = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hs = HandshakeState::new(Role::Responder, b_secret);

        let a = read_frame(&mut stream).await.unwrap();
        hs.read_message_a(&a).unwrap();

        let b = hs.write_message_b().unwrap();
        write_frame(&mut stream, &b).await.unwrap();

        let c = read_frame(&mut stream).await.unwrap();
        hs.read_message_c(&c).unwrap();

        let (send_cipher, recv_cipher) = hs.into_transport().unwrap();
        let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

        let msg = conn.recv_message().await.unwrap();
        assert_eq!(msg, Message::Ping(b"HidraPing".to_vec()));

        conn.send_message(&Message::Pong(b"HidraPong".to_vec()))
            .await
            .unwrap();
    });

    // Initiator (node A)
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut hs = HandshakeState::new(Role::Initiator, a_secret);

    let a = hs.write_message_a().unwrap();
    write_frame(&mut stream, &a).await.unwrap();

    let b = read_frame(&mut stream).await.unwrap();
    hs.read_message_b(&b).unwrap();

    let c = hs.write_message_c().unwrap();
    write_frame(&mut stream, &c).await.unwrap();

    let (send_cipher, recv_cipher) = hs.into_transport().unwrap();
    let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

    conn.send_message(&Message::Ping(b"HidraPing".to_vec()))
        .await
        .unwrap();

    let msg = conn.recv_message().await.unwrap();
    assert_eq!(msg, Message::Pong(b"HidraPong".to_vec()));

    responder.await.unwrap();
}

#[tokio::test]
async fn multiple_messages_after_handshake() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hs = HandshakeState::new(Role::Responder, b_secret);

        let a = read_frame(&mut stream).await.unwrap();
        hs.read_message_a(&a).unwrap();
        let b = hs.write_message_b().unwrap();
        write_frame(&mut stream, &b).await.unwrap();
        let c = read_frame(&mut stream).await.unwrap();
        hs.read_message_c(&c).unwrap();

        let (send_cipher, recv_cipher) = hs.into_transport().unwrap();
        let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

        for i in 0u32..10 {
            let msg = conn.recv_message().await.unwrap();
            let expected = format!("ping-{i}");
            assert_eq!(msg, Message::Ping(expected.into_bytes()));

            let reply = format!("pong-{i}");
            conn.send_message(&Message::Pong(reply.into_bytes()))
                .await
                .unwrap();
        }
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut hs = HandshakeState::new(Role::Initiator, a_secret);

    let a = hs.write_message_a().unwrap();
    write_frame(&mut stream, &a).await.unwrap();
    let b = read_frame(&mut stream).await.unwrap();
    hs.read_message_b(&b).unwrap();
    let c = hs.write_message_c().unwrap();
    write_frame(&mut stream, &c).await.unwrap();

    let (send_cipher, recv_cipher) = hs.into_transport().unwrap();
    let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

    for i in 0u32..10 {
        let payload = format!("ping-{i}");
        conn.send_message(&Message::Ping(payload.into_bytes()))
            .await
            .unwrap();

        let msg = conn.recv_message().await.unwrap();
        let expected = format!("pong-{i}");
        assert_eq!(msg, Message::Pong(expected.into_bytes()));
    }

    responder.await.unwrap();
}
