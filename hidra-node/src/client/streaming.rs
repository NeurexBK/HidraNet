//! A client's circuit, built by telescoping.
//!
//! The client opens one link, to the entry relay, and runs a handshake with
//! it. Every further hop is reached through the circuit itself: the client
//! asks the current last hop to EXTEND to the next relay and hands it a
//! handshake that only the next relay can answer. The middle and the exit
//! never see the client's address, and the client never opens a connection to
//! them; if an extension fails, the circuit is abandoned and nothing is tried
//! another way.
//!
//! Each hop's handshake starts from fresh ephemeral keys and authenticates
//! only the relay, against the key in its verified descriptor. The client
//! holds no long-term key here, so nothing it sends to one hop can be matched
//! with what it sends to another.

use rand::Rng;
use tokio::sync::mpsc;
use tracing::{debug, info};
use x25519_dalek::PublicKey;

use crate::crypto::circuit_handshake::Initiator;
use crate::error::{HidraError, Result};
use crate::network::connection::{LinkWriter, Message};
use crate::network::link;
use crate::onion::cell::RelayCommand;
use crate::onion::layer::{ClientHop, ClientLayers};
use crate::p2p::dht::descriptor::VerifiedRelay;

/// Hops in a circuit: entry, middle, exit.
pub const CIRCUIT_HOPS: usize = 3;

/// How long the client waits for a hop to answer during construction. An
/// EXTEND includes the relay's own dial and handshake to the next hop.
const BUILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct StreamingCircuit {
    link: LinkWriter,
    inbound: mpsc::Receiver<Result<Message>>,
    /// The circuit's id on the link to the entry, and nowhere else.
    circuit_id: u32,
    layers: ClientLayers,
}

impl StreamingCircuit {
    /// Builds a circuit through the first three relays of `path`, in order.
    ///
    /// The only connection this opens is to `path[0]`.
    pub async fn build(path: &[VerifiedRelay]) -> Result<Self> {
        if path.len() < CIRCUIT_HOPS {
            return Err(HidraError::Circuit(format!(
                "need {CIRCUIT_HOPS} relays for a circuit, have {}",
                path.len()
            )));
        }
        let path = &path[..CIRCUIT_HOPS];
        for (i, a) in path.iter().enumerate() {
            if path[..i]
                .iter()
                .any(|b| b.addr() == a.addr() || b.transport_key() == a.transport_key())
            {
                return Err(HidraError::Circuit("a relay appears twice in the path".into()));
            }
        }

        let conn = link::connect(path[0].addr(), path[0].transport_key()).await?;
        let (reader, mut writer) = conn.into_split();
        let mut inbound = reader.spawn();
        let circuit_id = rand::thread_rng().gen_range(1..=u32::MAX);

        let (init, msg_a) = Initiator::start(&PublicKey::from(*path[0].transport_key()))?;
        writer
            .send_message(&Message::Create { circuit_id, handshake: msg_a })
            .await?;
        let created = tokio::time::timeout(BUILD_TIMEOUT, inbound.recv())
            .await
            .map_err(|_| HidraError::Circuit("entry relay did not answer CREATE".into()))?;
        let msg_b = match created {
            Some(Ok(Message::Created { circuit_id: id, handshake })) if id == circuit_id => handshake,
            Some(Err(e)) => return Err(e),
            _ => return Err(HidraError::Circuit("entry relay refused CREATE".into())),
        };
        let mut layers = ClientLayers::new();
        layers.push(ClientHop::new(init.finish(&msg_b)?));
        debug!(hop = 0, "circuit hop established");

        let mut circuit = Self { link: writer, inbound, circuit_id, layers };
        for (i, relay) in path.iter().enumerate().skip(1) {
            if let Err(e) = circuit.extend(relay).await {
                circuit.destroy().await;
                return Err(e);
            }
            debug!(hop = i, "circuit hop established");
        }
        info!(hops = circuit.layers.len(), "circuit built");
        Ok(circuit)
    }

    async fn extend(&mut self, relay: &VerifiedRelay) -> Result<()> {
        let last = self.layers.len() - 1;
        let (init, msg_a) = Initiator::start(&PublicKey::from(*relay.transport_key()))?;
        self.send_to(
            last,
            &RelayCommand::Extend {
                addr: relay.addr(),
                transport_key: *relay.transport_key(),
                handshake: msg_a,
            },
        )
        .await?;
        let (from, answer) = tokio::time::timeout(BUILD_TIMEOUT, self.recv_command())
            .await
            .map_err(|_| HidraError::Circuit("extension timed out".into()))??;
        if from != last {
            return Err(HidraError::Circuit("an answer to EXTEND from the wrong hop".into()));
        }
        match answer {
            RelayCommand::Extended { handshake } => {
                // Fails unless the relay that answered holds the key its
                // descriptor names.
                self.layers.push(ClientHop::new(init.finish(&handshake)?));
                Ok(())
            }
            RelayCommand::ExtendFailed => Err(HidraError::Circuit("extension failed".into())),
            _ => Err(HidraError::Circuit("unexpected answer to EXTEND".into())),
        }
    }

    fn exit(&self) -> usize {
        self.layers.len() - 1
    }

    async fn send_to(&mut self, hop: usize, cmd: &RelayCommand) -> Result<()> {
        let cell = self.layers.seal(hop, &cmd.serialize_bincode()?)?;
        self.link
            .send_message(&Message::Relay { circuit_id: self.circuit_id, data: cell })
            .await
    }

    /// The next command any hop sends back, and which hop sent it.
    async fn recv_command(&mut self) -> Result<(usize, RelayCommand)> {
        match self.inbound.recv().await {
            Some(Ok(Message::Relay { circuit_id, data })) if circuit_id == self.circuit_id => {
                let (from, body) = self.layers.open(&data)?;
                Ok((from, RelayCommand::deserialize_bincode(&body)?))
            }
            Some(Ok(Message::Destroy { .. })) => Err(HidraError::Circuit("circuit destroyed".into())),
            Some(Ok(_)) => Err(HidraError::Protocol("unexpected message on the circuit link".into())),
            Some(Err(e)) => Err(e),
            None => Err(HidraError::Circuit("link to the entry relay closed".into())),
        }
    }

    /// The exit's answer to a request.
    async fn exit_answer(&mut self) -> Result<RelayCommand> {
        let (from, cmd) = self.recv_command().await?;
        if from != self.exit() {
            return Err(HidraError::Circuit("an answer from a hop that is not the exit".into()));
        }
        Ok(cmd)
    }

    pub async fn connect(&mut self, host: &str, port: u16) -> Result<()> {
        let exit = self.exit();
        self.send_to(exit, &RelayCommand::Connect { host: host.to_string(), port })
            .await?;
        match self.exit_answer().await? {
            RelayCommand::Connected => {
                debug!("circuit connected to target");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => {
                Err(HidraError::Circuit(format!("connect failed: {reason}")))
            }
            _ => Err(HidraError::Circuit("unexpected connect response".into())),
        }
    }

    pub async fn connect_service(&mut self, service_hash: Vec<u8>) -> Result<()> {
        let exit = self.exit();
        self.send_to(exit, &RelayCommand::ConnectService { service_hash }).await?;
        match self.exit_answer().await? {
            RelayCommand::ServiceConnected => {
                debug!("connected to hidden service");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => {
                Err(HidraError::Circuit(format!("service connect failed: {reason}")))
            }
            _ => Err(HidraError::Circuit("unexpected service connect response".into())),
        }
    }

    pub async fn register_service(&mut self, service_hash: Vec<u8>) -> Result<()> {
        let exit = self.exit();
        self.send_to(exit, &RelayCommand::RegisterService { service_hash }).await?;
        match self.exit_answer().await? {
            RelayCommand::ServiceRegistered => {
                info!("service registered at intro point");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => {
                Err(HidraError::Circuit(format!("service registration failed: {reason}")))
            }
            _ => Err(HidraError::Circuit("unexpected register response".into())),
        }
    }

    /// Sends a probe to the exit and returns its acknowledgement.
    pub async fn probe(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let exit = self.exit();
        self.send_to(exit, &RelayCommand::Probe(payload.to_vec())).await?;
        match self.exit_answer().await? {
            RelayCommand::ProbeReply(reply) => Ok(reply),
            _ => Err(HidraError::Circuit("unexpected probe response".into())),
        }
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        let exit = self.exit();
        self.send_to(exit, &RelayCommand::Data(data.to_vec())).await
    }

    /// The next piece of the stream, or `None` once the far end has closed it.
    /// Cancel-safe: it waits on a channel, and nothing is consumed until a
    /// message has arrived.
    pub async fn recv_data(&mut self) -> Result<Option<Vec<u8>>> {
        match self.exit_answer().await? {
            RelayCommand::Data(payload) => Ok(Some(payload)),
            RelayCommand::End => Ok(None),
            _ => Err(HidraError::Circuit("unexpected stream command".into())),
        }
    }

    pub async fn send_end(&mut self) -> Result<()> {
        let exit = self.exit();
        self.send_to(exit, &RelayCommand::End).await
    }

    /// Tears the circuit down at every hop.
    pub async fn destroy(&mut self) {
        let _ = self
            .link
            .send_message(&Message::Destroy { circuit_id: self.circuit_id })
            .await;
    }

    /// The circuit's id on the link to the entry relay. No other link uses it.
    pub fn circuit_id(&self) -> u32 {
        self.circuit_id
    }

    pub fn hop_count(&self) -> usize {
        self.layers.len()
    }
}
