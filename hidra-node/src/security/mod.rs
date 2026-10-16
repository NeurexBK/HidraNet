// ── Layer I: Rate Limiting & DDoS Protection ────────────────────────────
pub mod rate_limiter {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use crate::error::{HidraError, Result};
    use crate::safelog::sensitive;

    struct TokenBucket {
        tokens: f64,
        max_tokens: f64,
        refill_rate: f64,
        last_refill: Instant,
    }

    impl TokenBucket {
        fn new(max_tokens: f64, refill_rate: f64) -> Self {
            Self {
                tokens: max_tokens,
                max_tokens,
                refill_rate,
                last_refill: Instant::now(),
            }
        }

        fn try_consume(&mut self, cost: f64) -> bool {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
            self.last_refill = now;

            if self.tokens >= cost {
                self.tokens -= cost;
                true
            } else {
                false
            }
        }
    }

    struct PeerState {
        bucket: TokenBucket,
        connection_count: u32,
        first_seen: Instant,
        violations: u32,
        backoff_until: Option<Instant>,
    }

    pub struct RateLimiter {
        peers: Mutex<HashMap<IpAddr, PeerState>>,
        config: RateLimitConfig,
    }

    pub struct RateLimitConfig {
        pub max_requests_per_sec: f64,
        pub burst_size: f64,
        pub max_connections_per_ip: u32,
        pub max_violations_before_ban: u32,
        pub ban_duration: Duration,
        pub cleanup_interval: Duration,
    }

    impl Default for RateLimitConfig {
        fn default() -> Self {
            Self {
                max_requests_per_sec: 10.0,
                burst_size: 30.0,
                max_connections_per_ip: 8,
                max_violations_before_ban: 5,
                ban_duration: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(60),
            }
        }
    }

    impl RateLimiter {
        pub fn new(config: RateLimitConfig) -> Self {
            Self {
                peers: Mutex::new(HashMap::new()),
                config,
            }
        }

        pub fn check_rate_limit(&self, ip: IpAddr) -> Result<()> {
            let mut peers = self.peers.lock().map_err(|_| {
                HidraError::Protocol("rate limiter lock poisoned".into())
            })?;

            let now = Instant::now();
            let state = peers.entry(ip).or_insert_with(|| PeerState {
                bucket: TokenBucket::new(
                    self.config.burst_size,
                    self.config.max_requests_per_sec,
                ),
                connection_count: 0,
                first_seen: now,
                violations: 0,
                backoff_until: None,
            });

            if let Some(until) = state.backoff_until {
                if now < until {
                    return Err(HidraError::Protocol(
                        "peer is temporarily banned".into(),
                    ));
                }
                state.backoff_until = None;
                state.violations = 0;
            }

            if !state.bucket.try_consume(1.0) {
                state.violations += 1;
                if state.violations >= self.config.max_violations_before_ban {
                    let backoff = self.config.ban_duration
                        .mul_f64(2_f64.powi(
                            (state.violations - self.config.max_violations_before_ban)
                                .min(6) as i32,
                        ));
                    state.backoff_until = Some(now + backoff);
                    tracing::warn!(
                        peer = %sensitive(&ip),
                        violations = state.violations,
                        ban_secs = backoff.as_secs(),
                        "peer banned (exponential backoff)"
                    );
                }
                return Err(HidraError::Protocol("rate limit exceeded".into()));
            }

            Ok(())
        }

        pub fn track_connection(&self, ip: IpAddr) -> Result<()> {
            let mut peers = self.peers.lock().map_err(|_| {
                HidraError::Protocol("rate limiter lock poisoned".into())
            })?;

            let now = Instant::now();
            let state = peers.entry(ip).or_insert_with(|| PeerState {
                bucket: TokenBucket::new(
                    self.config.burst_size,
                    self.config.max_requests_per_sec,
                ),
                connection_count: 0,
                first_seen: now,
                violations: 0,
                backoff_until: None,
            });

            if state.connection_count >= self.config.max_connections_per_ip {
                return Err(HidraError::Protocol(format!(
                    "too many connections from one peer: {}",
                    state.connection_count
                )));
            }

            state.connection_count += 1;
            Ok(())
        }

        pub fn release_connection(&self, ip: IpAddr) {
            if let Ok(mut peers) = self.peers.lock() {
                if let Some(state) = peers.get_mut(&ip) {
                    state.connection_count = state.connection_count.saturating_sub(1);
                }
            }
        }

        pub fn cleanup_stale(&self) {
            if let Ok(mut peers) = self.peers.lock() {
                let now = Instant::now();
                peers.retain(|_, state| {
                    let idle = now.duration_since(state.first_seen);
                    state.connection_count > 0
                        || idle < self.config.cleanup_interval
                        || state.backoff_until.map_or(false, |u| now < u)
                });
            }
        }
    }
}

// ── Layer I: Proof-of-Work for Sybil Resistance ─────────────────────────
pub mod pow {
    use crate::error::{HidraError, Result};

    pub const DEFAULT_DIFFICULTY: u32 = 20;
    const MAX_NONCE_ATTEMPTS: u64 = 1 << 30;

    pub struct PowChallenge {
        pub challenge: [u8; 32],
        pub difficulty: u32,
        pub timestamp: u64,
    }

    pub struct PowSolution {
        pub nonce: u64,
        pub hash: [u8; 32],
    }

    pub fn generate_challenge(difficulty: u32) -> PowChallenge {
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        PowChallenge {
            challenge,
            difficulty,
            timestamp,
        }
    }

    pub fn solve_challenge(challenge: &PowChallenge) -> Result<PowSolution> {
        for nonce in 0..MAX_NONCE_ATTEMPTS {
            let hash = compute_pow_hash(&challenge.challenge, nonce);
            if check_leading_zeros(&hash, challenge.difficulty) {
                return Ok(PowSolution { nonce, hash });
            }
        }
        Err(HidraError::Protocol("PoW: exceeded max nonce attempts".into()))
    }

    pub fn verify_solution(
        challenge: &PowChallenge,
        solution: &PowSolution,
        max_age_secs: u64,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(challenge.timestamp) > max_age_secs {
            return Err(HidraError::Protocol("PoW challenge expired".into()));
        }

        let expected = compute_pow_hash(&challenge.challenge, solution.nonce);
        if !constant_time_eq(&expected, &solution.hash) {
            return Err(HidraError::Protocol("PoW hash mismatch".into()));
        }
        if !check_leading_zeros(&solution.hash, challenge.difficulty) {
            return Err(HidraError::Protocol("PoW insufficient difficulty".into()));
        }
        Ok(())
    }

    fn compute_pow_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(challenge);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn check_leading_zeros(hash: &[u8; 32], difficulty: u32) -> bool {
        let full_bytes = (difficulty / 8) as usize;
        let remaining_bits = difficulty % 8;

        for &byte in &hash[..full_bytes.min(32)] {
            if byte != 0 {
                return false;
            }
        }
        if remaining_bits > 0 && full_bytes < 32 {
            let mask = 0xFF_u8 << (8 - remaining_bits);
            if hash[full_bytes] & mask != 0 {
                return false;
            }
        }
        true
    }

    fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
}

// ── Layer I: Traffic Padding & Chaffing ──────────────────────────────────
pub mod traffic {
    use crate::error::{HidraError, Result};

    pub const PADDED_CELL_SIZE: usize = 512;
    const CHAFF_MARKER: u8 = 0xFF;
    const DATA_MARKER: u8 = 0x00;

    pub fn pad_message(payload: &[u8]) -> Result<Vec<u8>> {
        let max_payload = PADDED_CELL_SIZE - 1 - 2;
        if payload.len() > max_payload {
            return Err(HidraError::Protocol(format!(
                "payload too large for padding: {} > {max_payload}",
                payload.len()
            )));
        }

        let mut cell = Vec::with_capacity(PADDED_CELL_SIZE);
        cell.push(DATA_MARKER);
        let len = payload.len() as u16;
        cell.extend_from_slice(&len.to_be_bytes());
        cell.extend_from_slice(payload);

        let pad_len = PADDED_CELL_SIZE - cell.len();
        let mut padding = vec![0u8; pad_len];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
        cell.extend_from_slice(&padding);

        debug_assert_eq!(cell.len(), PADDED_CELL_SIZE);
        Ok(cell)
    }

    pub fn unpad_message(cell: &[u8]) -> Result<Vec<u8>> {
        if cell.len() != PADDED_CELL_SIZE {
            return Err(HidraError::Protocol(format!(
                "invalid padded cell size: {} != {PADDED_CELL_SIZE}",
                cell.len()
            )));
        }

        if cell[0] == CHAFF_MARKER {
            return Err(HidraError::Protocol("chaff packet — discard".into()));
        }

        if cell[0] != DATA_MARKER {
            return Err(HidraError::Protocol(format!(
                "unknown cell marker: 0x{:02X}",
                cell[0]
            )));
        }

        let len = u16::from_be_bytes([cell[1], cell[2]]) as usize;
        let max_payload = PADDED_CELL_SIZE - 3;
        if len > max_payload {
            return Err(HidraError::Protocol("invalid payload length in cell".into()));
        }

        Ok(cell[3..3 + len].to_vec())
    }

    pub fn generate_chaff() -> Vec<u8> {
        let mut cell = vec![0u8; PADDED_CELL_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cell);
        cell[0] = CHAFF_MARKER;
        cell
    }

    pub fn is_chaff(cell: &[u8]) -> bool {
        cell.first() == Some(&CHAFF_MARKER)
    }

    pub async fn random_delay(min_ms: u64, max_ms: u64) {
        use rand::Rng;
        let delay_ms = rand::thread_rng().gen_range(min_ms..=max_ms);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
}

// ── Layer II: Post-Quantum Hybrid Handshake (ML-KEM-1024 + X25519) ──────
//
// The post-quantum half is FIPS 203 ML-KEM-1024. It used to be pqc_kyber
// 0.7.1, which is unmaintained and has no fixed release: its AVX2 backend
// skips the Fujisaki-Okamoto implicit rejection step (RUSTSEC-2026-0290),
// so an attacker who can feed it chosen ciphertexts recovers the
// decapsulation key outright, and its division timings leak the secret
// (RUSTSEC-2023-0079, KyberSlash). Both are fatal to the one property this
// layer exists to provide, on exactly the x86-64 machines the browser runs
// on.
//
// Hybrid, not ML-KEM alone: a break of either primitive still leaves the
// other standing, because the session key is a hash of both secrets and
// neither half can be reconstructed from the other.
pub mod post_quantum {
    use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
    use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::error::{HidraError, Result};

    /// Domain separator for the combiner. Bumped from v1 with the move off
    /// Kyber round-3: a v1 and a v2 peer derive different keys and simply
    /// fail to talk, which is the outcome we want — there is no downgrade
    /// to the broken construction.
    const COMBINER_DOMAIN: &[u8] = b"HidraNet-Hybrid-KEM-v2-MLKEM1024-X25519";

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct HybridSharedSecret {
        combined: [u8; 32],
    }

    impl HybridSharedSecret {
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.combined
        }
    }

    pub struct HybridKeyPair {
        pub x25519_secret: StaticSecret,
        pub x25519_public: X25519Public,
        /// ML-KEM-1024 encapsulation key, as it goes on the wire.
        pub kyber_public: Vec<u8>,
        /// Decapsulation key. Kept as the library's own type rather than
        /// loose bytes so it is never accidentally serialized, logged or
        /// copied, and so it zeroizes itself on drop.
        decapsulation_key: DecapsulationKey,
    }

    impl HybridKeyPair {
        pub fn generate() -> Result<Self> {
            let mut rng = rand::thread_rng();
            let x25519_secret = StaticSecret::random_from_rng(&mut rng);
            let x25519_public = X25519Public::from(&x25519_secret);

            let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();

            Ok(Self {
                x25519_secret,
                x25519_public,
                kyber_public: encapsulation_key.to_bytes().to_vec(),
                decapsulation_key,
            })
        }
    }

    pub struct HybridEncapsulation {
        pub x25519_ephemeral_public: [u8; 32],
        pub kyber_ciphertext: Vec<u8>,
    }

    pub fn hybrid_encapsulate(
        peer_x25519_public: &X25519Public,
        peer_kyber_public: &[u8],
    ) -> Result<(HybridSharedSecret, HybridEncapsulation)> {
        let mut rng = rand::thread_rng();

        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);
        let x25519_shared = ephemeral_secret.diffie_hellman(peer_x25519_public);

        // A peer who sends a low-order point forces the shared secret to
        // all zeroes, which would let it fix half the combiner input.
        if !x25519_shared.was_contributory() {
            return Err(HidraError::Crypto(
                "X25519 peer key is a low-order point".into(),
            ));
        }

        // Rejects a malformed or non-canonical encapsulation key rather
        // than encapsulating to it.
        let encapsulation_key = EncapsulationKey::new_from_slice(peer_kyber_public)
            .map_err(|_| HidraError::Crypto("ML-KEM encapsulation key rejected".into()))?;

        let (kyber_ct, mut kyber_shared) = encapsulation_key.encapsulate();

        let combined = combine_secrets(
            x25519_shared.as_bytes(),
            &kyber_shared,
            ephemeral_public.as_bytes(),
            &kyber_ct,
            peer_kyber_public,
        );
        kyber_shared.as_mut_slice().zeroize();

        Ok((
            HybridSharedSecret { combined },
            HybridEncapsulation {
                x25519_ephemeral_public: *ephemeral_public.as_bytes(),
                kyber_ciphertext: kyber_ct.to_vec(),
            },
        ))
    }

    pub fn hybrid_decapsulate(
        own_keys: &HybridKeyPair,
        encapsulation: &HybridEncapsulation,
    ) -> Result<HybridSharedSecret> {
        let peer_ephemeral = X25519Public::from(encapsulation.x25519_ephemeral_public);
        let x25519_shared = own_keys.x25519_secret.diffie_hellman(&peer_ephemeral);

        if !x25519_shared.was_contributory() {
            return Err(HidraError::Crypto(
                "X25519 peer key is a low-order point".into(),
            ));
        }

        let ciphertext = Ciphertext::try_from(encapsulation.kyber_ciphertext.as_slice())
            .map_err(|_| {
                HidraError::Crypto("ML-KEM ciphertext has the wrong length".into())
            })?;

        // ML-KEM decapsulation never reports failure: a bad ciphertext
        // yields an unrelated key by implicit rejection, which is what
        // denies a chosen-ciphertext attacker the oracle it needs. The
        // mismatch surfaces later, when the AEAD tag does not verify.
        let mut kyber_shared = own_keys.decapsulation_key.decapsulate(&ciphertext);

        let combined = combine_secrets(
            x25519_shared.as_bytes(),
            &kyber_shared,
            &encapsulation.x25519_ephemeral_public,
            &encapsulation.kyber_ciphertext,
            &own_keys.kyber_public,
        );
        kyber_shared.as_mut_slice().zeroize();

        Ok(HybridSharedSecret { combined })
    }

    /// Both secrets plus the full transcript. Hashing the ciphertexts and
    /// the encapsulation key in as well — not just the two secrets — is
    /// what keeps the combined key bound to this exchange: a peer cannot
    /// replay one half against a different transcript and land on the same
    /// session key. Lengths are prefixed so no two different transcripts
    /// can serialize to the same byte string.
    fn combine_secrets(
        x25519: &[u8; 32],
        mlkem: &[u8],
        x25519_ephemeral_public: &[u8; 32],
        mlkem_ciphertext: &[u8],
        mlkem_encapsulation_key: &[u8],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COMBINER_DOMAIN);
        for part in [
            x25519.as_slice(),
            mlkem,
            x25519_ephemeral_public.as_slice(),
            mlkem_ciphertext,
            mlkem_encapsulation_key,
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }
}

// ── Layer III: Encrypted Local Storage Vault ─────────────────────────────
pub mod vault {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use argon2::Argon2;
    use zeroize::Zeroize;

    use crate::error::{HidraError, Result};

    const SALT_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const KEY_LEN: usize = 32;
    const VAULT_MAGIC: &[u8; 4] = b"HVLT";
    const VAULT_VERSION: u8 = 1;

    pub struct VaultConfig {
        pub argon2_m_cost: u32,
        pub argon2_t_cost: u32,
        pub argon2_p_cost: u32,
    }

    impl Default for VaultConfig {
        fn default() -> Self {
            Self {
                argon2_m_cost: 65536,
                argon2_t_cost: 3,
                argon2_p_cost: 4,
            }
        }
    }

    fn derive_key(
        passphrase: &[u8],
        salt: &[u8],
        config: &VaultConfig,
    ) -> Result<[u8; KEY_LEN]> {
        let params = argon2::Params::new(
            config.argon2_m_cost,
            config.argon2_t_cost,
            config.argon2_p_cost,
            Some(KEY_LEN),
        )
        .map_err(|e| HidraError::Crypto(format!("Argon2 params error: {e}")))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| HidraError::Crypto(format!("Argon2id KDF failed: {e}")))?;
        Ok(key)
    }

    pub fn vault_encrypt(
        passphrase: &[u8],
        plaintext: &[u8],
        config: &VaultConfig,
    ) -> Result<Vec<u8>> {
        let mut salt = [0u8; SALT_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

        let mut key = derive_key(passphrase, &salt, config)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| HidraError::Crypto("AES-256-GCM key init failed".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| HidraError::Crypto("AES-256-GCM encryption failed".into()))?;

        key.zeroize();

        // Format: MAGIC(4) | VERSION(1) | SALT(32) | NONCE(12) | CIPHERTEXT(var)
        let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(VAULT_MAGIC);
        out.push(VAULT_VERSION);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    pub fn vault_decrypt(
        passphrase: &[u8],
        sealed: &[u8],
        config: &VaultConfig,
    ) -> Result<Vec<u8>> {
        let header_len = 4 + 1 + SALT_LEN + NONCE_LEN;
        if sealed.len() < header_len + 16 {
            return Err(HidraError::Crypto("vault data too short".into()));
        }

        if &sealed[..4] != VAULT_MAGIC {
            return Err(HidraError::Crypto("invalid vault magic".into()));
        }
        if sealed[4] != VAULT_VERSION {
            return Err(HidraError::Crypto(format!(
                "unsupported vault version: {}",
                sealed[4]
            )));
        }

        let salt = &sealed[5..5 + SALT_LEN];
        let nonce_bytes = &sealed[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
        let ciphertext = &sealed[header_len..];

        let mut key = derive_key(passphrase, salt, config)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| HidraError::Crypto("AES-256-GCM key init failed".into()))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| {
                HidraError::Crypto(
                    "AES-256-GCM decryption failed — wrong passphrase or tampered data".into(),
                )
            })?;

        key.zeroize();
        Ok(plaintext)
    }

    pub fn vault_store(
        path: &std::path::Path,
        passphrase: &[u8],
        data: &[u8],
    ) -> Result<()> {
        let config = VaultConfig::default();
        let sealed = vault_encrypt(passphrase, data, &config)?;
        // Owner-only from the moment it exists, like every other secret.
        crate::crypto::keys::write_private_file(path, &sealed)
    }

    pub fn vault_load(path: &std::path::Path, passphrase: &[u8]) -> Result<Vec<u8>> {
        let sealed = std::fs::read(path)?;
        let config = VaultConfig::default();
        vault_decrypt(passphrase, &sealed, &config)
    }
}

// ── Layer IV: Constant-Time Operations & System Hardening ────────────────
pub mod hardening {
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    pub fn secure_random_bytes(buf: &mut [u8]) {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
    }

    pub fn secure_random_u64() -> u64 {
        let mut buf = [0u8; 8];
        secure_random_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    #[cfg(target_os = "linux")]
    pub fn disable_core_dumps() -> std::io::Result<()> {
        unsafe {
            let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0);
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn disable_core_dumps() -> std::io::Result<()> {
        Ok(())
    }

    /// Install a panic hook that says where, not what.
    ///
    /// The default hook prints the panic payload, and a payload is whatever
    /// string the failing code built: an `expect` on a parse carries the
    /// text it was parsing, which on a relay can be a peer address or a
    /// destination. The location is enough to find the bug. The payload is
    /// printed only when the operator has turned unsafe logging on.
    ///
    /// The name is historical. It never zeroized anything; secrets are wiped
    /// by their own `Drop`, which runs during unwinding like any other.
    pub fn zeroize_on_panic() {
        std::panic::set_hook(Box::new(|info| {
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "unknown location".to_string());
            if crate::safelog::unsafe_logging() {
                eprintln!("PANIC at {location}: {info}");
            } else {
                eprintln!(
                    "PANIC at {location} (message withheld; set logging.unsafe_addresses \
                     to print it)"
                );
            }
        }));
    }
}
