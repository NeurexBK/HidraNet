//! Only the holder of a `.hidra` address's key can be that address.
//!
//! An introduction relay used to register whoever asked for a service hash,
//! with no proof, replacing whoever had it before, and the client never
//! checked who answered. These run real relays and real circuits: the real
//! service registers and serves; an impostor cannot register the address,
//! with no proof, with a forged one or with someone else's; and the client
//! refuses to talk to a service that cannot prove the address's key.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::crypto::service_auth::answer_hello;
use hidra_node::network::listener::NodeListener;
use hidra_node::p2p::dht::descriptor::service_hash_of;
use hidra_node::relay::exit_policy::ExitPolicy;
use hidra_node::relay::registry::RelayEntry;

async fn relays() -> Vec<RelayEntry> {
    let mut out = Vec::new();
    for i in 0..3 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = BASE64.encode(PublicKey::from(&secret).to_bytes());
        let l = NodeListener::bind("127.0.0.1:0".parse().unwrap(), secret)
            .await
            .unwrap()
            .with_exit_policy(ExitPolicy::ALLOW_PRIVATE);
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { l.accept_loop().await });
        out.push(RelayEntry {
            name: format!("r{i}"),
            addr,
            noise_pubkey_b64: key,
        });
    }
    out
}

async fn circuit(relays: &[RelayEntry]) -> StreamingCircuit {
    StreamingCircuit::build(relays, StaticSecret::random_from_rng(OsRng))
        .await
        .unwrap()
}

/// The service side, as `run_hidden_service` runs it: answer the challenge
/// with the address's key, then echo what arrives sealed, sealed.
fn serve(mut svc: StreamingCircuit, key: SigningKey) {
    tokio::spawn(async move {
        let mut channel = None;
        while let Ok(Some(raw)) = svc.recv_raw().await {
            if hidra_node::crypto::service_auth::is_hello(&raw) {
                let (ch, answer) = answer_hello(&key, &raw).unwrap();
                svc.send_raw(&answer).await.unwrap();
                channel = Some(ch);
                continue;
            }
            let Some(ch) = channel.as_mut() else { continue };
            let Ok(data) = ch.open(&raw) else { break };
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&data);
            let sealed = ch.seal(&reply).unwrap();
            svc.send_raw(&sealed).await.unwrap();
        }
    });
}

#[tokio::test]
async fn the_real_service_registers_and_its_clients_reach_it() {
    let r = relays().await;
    let key = SigningKey::generate(&mut OsRng);
    let pk = key.verifying_key().to_bytes();
    let mut svc = circuit(&r).await;
    svc.register_service(&key)
        .await
        .expect("the key holder must be able to register");
    serve(svc, key);

    // The client's circuit ends at the introduction point: the same last relay.
    let mut client = circuit(&[r[1].clone(), r[0].clone(), r[2].clone()]).await;
    client
        .connect_service_authenticated(&pk)
        .await
        .expect("the real service must prove itself");
    client.send_data(b"hello").await.unwrap();
    assert_eq!(client.recv_data().await.unwrap().unwrap(), b"echo:hello");
    client.send_data(b"again").await.unwrap();
    assert_eq!(client.recv_data().await.unwrap().unwrap(), b"echo:again");
    client.send_end().await.unwrap();
    drop(client);

    // And the way the SOCKS proxy gets there: a circuit the pool builds to
    // end at the introduction point the descriptor names.
    let pool = hidra_node::client::circuit_pool::CircuitPool::new(
        StaticSecret::random_from_rng(OsRng).to_bytes(),
        r.clone(),
    );
    let mut via = pool.build_circuit_via(r[2].addr).await.unwrap();
    via.connect_service_authenticated(&pk)
        .await
        .expect("the pool's circuit reaches the service");
    via.send_data(b"pool").await.unwrap();
    assert_eq!(via.recv_data().await.unwrap().unwrap(), b"echo:pool");
}

#[tokio::test]
async fn an_impostor_cannot_register_someone_elses_address() {
    let r = relays().await;
    let real = SigningKey::generate(&mut OsRng);
    let real_pk = real.verifying_key().to_bytes();
    let mut svc = circuit(&r).await;
    svc.register_service(&real).await.unwrap();
    serve(svc, real);

    // The impostor's own key registers only the impostor's own address,
    // never the real one: the address is the hash of the key.
    let impostor = SigningKey::generate(&mut OsRng);
    let mut evil = circuit(&r).await;
    evil.register_service(&impostor).await.unwrap();
    assert_ne!(
        service_hash_of(&impostor.verifying_key().to_bytes()),
        service_hash_of(&real_pk)
    );

    // And the real address still reaches the real service.
    let mut client = circuit(&[r[0].clone(), r[1].clone(), r[2].clone()]).await;
    client
        .connect_service_authenticated(&real_pk)
        .await
        .unwrap();
    client.send_data(b"who").await.unwrap();
    assert_eq!(client.recv_data().await.unwrap().unwrap(), b"echo:who");
}

#[tokio::test]
async fn a_forged_registration_is_refused_by_the_relay() {
    use hidra_node::onion::cell::RelayCommand;
    let r = relays().await;
    let real = SigningKey::generate(&mut OsRng);
    let real_pk = real.verifying_key().to_bytes();
    let impostor = SigningKey::generate(&mut OsRng);
    let (_, ts, forged_sig) = hidra_node::crypto::service_auth::registration_proof(&impostor);

    // Built by hand, the way an attacker would send it: the real address and
    // key, with a signature that key never made; then no proof at all.
    for (pk, sig) in [
        (real_pk, forged_sig.clone()),
        (real_pk, vec![0u8; 64]),
        (real_pk, Vec::new()),
    ] {
        let mut evil = circuit(&r).await;
        let cmd = RelayCommand::RegisterService {
            service_hash: service_hash_of(&real_pk).to_vec(),
            service_pubkey: pk,
            timestamp: ts,
            signature: sig,
        };
        let res = evil.request(&cmd).await.unwrap();
        assert!(
            matches!(res, RelayCommand::ConnectFailed(_)),
            "the relay accepted a registration it could not verify: {res:?}"
        );
    }

    // Nobody registered it, so a client finds nothing there to talk to.
    let mut client = circuit(&r).await;
    assert!(
        client
            .connect_service_authenticated(&real_pk)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_client_refuses_a_service_that_cannot_prove_the_key() {
    let r = relays().await;
    // A service registered under its own key, answering with that key...
    let svc_key = SigningKey::generate(&mut OsRng);
    let mut svc = circuit(&r).await;
    svc.register_service(&svc_key).await.unwrap();
    // ...but signing its answers with another: what a relay that swapped in
    // its own responder would have to do.
    serve(svc, SigningKey::generate(&mut OsRng));
    let mut client = circuit(&r).await;
    let err = client
        .connect_service_authenticated(&svc_key.verifying_key().to_bytes())
        .await
        .expect_err("a service that cannot sign for its address must be refused");
    assert!(format!("{err}").contains("authentication"), "got: {err}");
}
