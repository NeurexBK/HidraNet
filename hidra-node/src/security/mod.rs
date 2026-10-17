//! Defence-in-depth helpers.
//!
//! What the binary uses: `hardening` (the panic hook and the core-dump
//! switch, at startup). The other three modules — a token-bucket rate
//! limiter, a proof-of-work puzzle and fixed-size cell padding with chaff —
//! are complete and tested but NOT wired into any listener or circuit. They
//! are kept as the starting point for the day padding and admission control
//! are designed properly; nothing in SECURITY.md claims them, and the
//! anonymity panel in the browser does not either. Two further modules that
//! used to live here, a second hybrid KEM and an AES-GCM vault, duplicated
//! `crypto::handshake` and `crypto::keystore` and were removed; the history
//! has them.

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
            if let Ok(mut peers) = self.peers.lock()
                && let Some(state) = peers.get_mut(&ip)
            {
                state.connection_count = state.connection_count.saturating_sub(1);
            }
        }

        pub fn cleanup_stale(&self) {
            if let Ok(mut peers) = self.peers.lock() {
                let now = Instant::now();
                peers.retain(|_, state| {
                    let idle = now.duration_since(state.first_seen);
                    state.connection_count > 0
                        || idle < self.config.cleanup_interval
                        || state.backoff_until.is_some_and(|u| now < u)
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
