//! The HidraVPN pass issuer (phase 5).
//!
//!   hidravpn-issuer keygen --out issuer-key.json [--days 35]   a new signing key; prints its record
//!   hidravpn-issuer record --key issuer-key.json               the record again, for the list and the nodes
//!   hidravpn-issuer account add --name NAME --quota N          a new account; prints its token once
//!   hidravpn-issuer account list | disable NAME | enable NAME
//!   hidravpn-issuer run --key issuer-key.json [--key ...]      serve POST /issue
//!
//! What it does: an account that is enabled and under its daily quota sends
//! blinded pass messages and gets them back signed. It never sees what it
//! signs, so it never learns which node a pass is for, nor the key a pass
//! admits; a node that takes the pass never learns which account it came
//! from. What it keeps: its key, and per account a name, the SHA-256 of the
//! token (never the token), the quota and today's count. It logs counts,
//! never an account, a token or an address.
//!
//! It speaks plain HTTP on 127.0.0.1 by default and is meant to sit behind a
//! TLS reverse proxy: a token on the open internet only travels encrypted.
//! It refuses another address without `--plain-http-public`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use clap::{Parser, Subcommand};
use hidravpn_core::admission::{http_response, read_request, refusal};
use hidravpn_core::pass::{
    IssueRequest, IssueResponse, IssuerSecret, PassKeyRecord, MAX_PER_REQUEST,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

const CONNECTIONS: usize = 64;
const PER_CONNECTION: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(
    name = "hidravpn-issuer",
    version,
    about = "HidraVPN pass issuer: signs passes blind for accounts"
)]
struct Cli {
    /// The accounts file.
    #[arg(
        long,
        global = true,
        default_value = "/var/lib/hidravpn-issuer/accounts.json"
    )]
    accounts: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new issuer key. Passes made under it are accepted until it
    /// expires; make the next one before that and publish both.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// How many days passes under this key stay valid.
        #[arg(long, default_value_t = 35)]
        days: u32,
    },
    /// Print a key's record: what the signed list and each node carry.
    Record {
        #[arg(long)]
        key: PathBuf,
    },
    /// The accounts that may get passes.
    Account {
        #[command(subcommand)]
        what: Account,
    },
    /// Serve `POST /issue` until stopped.
    Run {
        /// An issuer key; give the current one and the next during a rotation.
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:8730")]
        listen: SocketAddr,
        /// Listen on an address that is not loopback with plain HTTP. Only
        /// on a private network or behind a TLS proxy on the same host.
        #[arg(long)]
        plain_http_public: bool,
    },
}

#[derive(Subcommand)]
enum Account {
    /// Add an account and print its token, once.
    Add {
        #[arg(long)]
        name: String,
        /// Passes per day (UTC).
        #[arg(long, default_value_t = 100)]
        quota: u32,
    },
    List,
    Disable {
        name: String,
    },
    Enable {
        name: String,
    },
}

// ---- the key file ------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct KeyFile {
    /// The secret key, DER, base64. Readable by the issuer only.
    secret: String,
    record: PassKeyRecord,
}

fn load_key(path: &Path) -> Result<(IssuerSecret, PassKeyRecord)> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let k: KeyFile = serde_json::from_str(&s).context("the key file is not valid")?;
    let secret = IssuerSecret::from_der_base64(&k.secret)?;
    k.record.validate()?;
    if k.record.id != secret.public().id_hex() {
        return Err(anyhow!("the key file's record does not match its secret"));
    }
    Ok((secret, k.record))
}

fn write_private(path: &Path, bytes: &[u8], create_new: bool) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if create_new {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

// ---- accounts ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountEntry {
    name: String,
    /// SHA-256 of the token, hex. The token itself is shown once and kept
    /// nowhere here.
    token_sha256: String,
    quota_per_day: u32,
    #[serde(default = "yes")]
    enabled: bool,
    /// The UTC day (days since the epoch) `used` counts.
    #[serde(default)]
    day: i64,
    #[serde(default)]
    used: u32,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Accounts {
    #[serde(default)]
    accounts: Vec<AccountEntry>,
}

/// Why an issuance is refused, with the HTTP status it is answered with.
#[derive(Debug, PartialEq)]
enum Refused {
    UnknownToken,
    Disabled,
    Quota { left: u32 },
}

impl Accounts {
    fn load(path: &Path) -> Result<Accounts> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).context("the accounts file is not valid"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Accounts::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Loads, changes and saves the file under a lock on the file system,
    /// so the running issuer and an `account` command never undo each
    /// other's change. The lock is held only for the time of `f`.
    fn update<T>(path: &Path, f: impl FnOnce(&mut Accounts) -> T) -> Result<T> {
        let _held = lock_file(path)?;
        let mut a = Accounts::load(path)?;
        let out = f(&mut a);
        a.save(path)?;
        Ok(out)
    }

    /// Written beside and renamed over, so a reader never sees half a file.
    /// The temporary name is this process's own.
    fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
        write_private(&tmp, serde_json::to_string_pretty(self)?.as_bytes(), false)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn add(&mut self, name: &str, quota: u32) -> Result<String> {
        let name = name.trim();
        if name.is_empty()
            || name.len() > 32
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("an account name is 1-32 letters, digits, - or _"));
        }
        if self.accounts.iter().any(|a| a.name == name) {
            return Err(anyhow!("there is already an account named {name}"));
        }
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|e| anyhow!("no randomness available: {e}"))?;
        let token = B64URL.encode(raw);
        self.accounts.push(AccountEntry {
            name: name.to_string(),
            token_sha256: token_hash(&token),
            quota_per_day: quota,
            enabled: true,
            day: 0,
            used: 0,
        });
        Ok(token)
    }

    /// Gives back `n` passes counted today and never signed.
    fn refund(&mut self, token: &str, n: u32, today: i64) {
        let h = token_hash(token);
        if let Some(a) = self
            .accounts
            .iter_mut()
            .find(|a| same(a.token_sha256.as_bytes(), h.as_bytes()))
        {
            if a.day == today {
                a.used = a.used.saturating_sub(n);
            }
        }
    }

    fn set_enabled(&mut self, name: &str, on: bool) -> Result<()> {
        let a = self
            .accounts
            .iter_mut()
            .find(|a| a.name == name.trim())
            .ok_or_else(|| anyhow!("no account named {name}"))?;
        a.enabled = on;
        Ok(())
    }

    /// Counts `n` passes against the account the token names, today, if it
    /// may have them; all or nothing. Returns how many it has left.
    fn charge(&mut self, token: &str, n: u32, today: i64) -> std::result::Result<u32, Refused> {
        let h = token_hash(token);
        let a = self
            .accounts
            .iter_mut()
            .find(|a| same(a.token_sha256.as_bytes(), h.as_bytes()))
            .ok_or(Refused::UnknownToken)?;
        if !a.enabled {
            return Err(Refused::Disabled);
        }
        if a.day != today {
            a.day = today;
            a.used = 0;
        }
        let left = a.quota_per_day.saturating_sub(a.used);
        if n > left {
            return Err(Refused::Quota { left });
        }
        a.used += n;
        Ok(left - n)
    }
}

/// An exclusive lock beside the accounts file, released when the returned
/// file is dropped. It blocks until the other holder is done.
fn lock_file(accounts: &Path) -> Result<std::fs::File> {
    if let Some(d) = accounts.parent() {
        std::fs::create_dir_all(d)?;
    }
    let lock = accounts.with_extension("lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock)
        .with_context(|| format!("opening {}", lock.display()))?;
    f.lock()
        .with_context(|| format!("locking {}", lock.display()))?;
    Ok(f)
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

/// Compared without a short cut, so the time taken says nothing.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn today() -> i64 {
    hidravpn_core::timefmt::now_unix().div_euclid(86_400)
}

fn rfc3339(unix: i64) -> String {
    // Days to a civil date (Howard Hinnant's algorithm, the inverse of the
    // one timefmt uses), midnight UTC.
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

// ---- the service --------------------------------------------------------------

struct Issuer {
    keys: Vec<(IssuerSecret, PassKeyRecord)>,
    accounts_path: PathBuf,
    /// One issuance at a time: load, charge, save is one step, so an
    /// `account add` made while the issuer runs is never lost.
    lock: Mutex<()>,
}

impl Issuer {
    async fn issue(self: &Arc<Self>, body: &[u8]) -> (u16, String) {
        let req: IssueRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => {
                return (
                    400,
                    refusal("the request is not {\"token\", \"key_id\", \"blinded\": [...]}"),
                )
            }
        };
        if req.blinded.is_empty() || req.blinded.len() > MAX_PER_REQUEST {
            return (
                400,
                refusal(format!("ask for 1 to {MAX_PER_REQUEST} passes at a time")),
            );
        }
        let now = hidravpn_core::timefmt::now_unix();
        let Some(key_index) = self
            .keys
            .iter()
            .position(|(_, r)| r.id.eq_ignore_ascii_case(req.key_id.trim()) && r.is_current(now))
        else {
            return (
                400,
                refusal("this issuer does not sign under that key (unknown or expired); import a newer node list"),
            );
        };
        // The shape is checked first, for nothing; then the account is
        // charged; only then is anything signed. Nobody without an account
        // and a quota left gets the issuer to use its secret key.
        if req.blinded.iter().any(|b| !looks_blinded(b)) {
            return (400, refusal("a blinded message is not one"));
        }
        let n = req.blinded.len() as u32;
        let day = today();
        let token = req.token.clone();
        let path = self.accounts_path.clone();
        let charged = {
            let _one_at_a_time = self.lock.lock().await;
            tokio::task::spawn_blocking(move || {
                Accounts::update(&path, |a| a.charge(&token, n, day))
            })
            .await
        };
        let left = match charged {
            Ok(Ok(Ok(left))) => left,
            Ok(Ok(Err(Refused::UnknownToken))) => {
                return (403, refusal("that is not an account token here"))
            }
            Ok(Ok(Err(Refused::Disabled))) => {
                return (
                    403,
                    refusal("this account is switched off; ask the issuer's operator"),
                )
            }
            Ok(Ok(Err(Refused::Quota { left }))) => {
                return (
                    429,
                    refusal(format!(
                    "today's quota is reached for that many: {left} left; try again tomorrow (UTC)"
                )),
                )
            }
            Ok(Err(e)) => {
                warn!("accounts: {e:#}");
                return (503, refusal("the issuer cannot read or write its accounts"));
            }
            Err(_) => return (503, refusal("the issuer could not count the passes")),
        };
        // Signing is slow arithmetic: off the threads that serve connections.
        let me = self.clone();
        let blinded = req.blinded;
        let signed = tokio::task::spawn_blocking(move || {
            let secret = &me.keys[key_index].0;
            blinded
                .iter()
                .map(|b| secret.sign_blinded(b))
                .collect::<Result<Vec<String>>>()
        })
        .await;
        match signed {
            Ok(Ok(signatures)) => {
                info!("issued {n} pass(es)");
                let resp = IssueResponse {
                    signatures,
                    remaining_today: left,
                };
                (
                    200,
                    serde_json::to_string(&resp).expect("an answer serialises"),
                )
            }
            _ => {
                // Counted and not signed: given back.
                let path = self.accounts_path.clone();
                let token = req.token;
                let _one_at_a_time = self.lock.lock().await;
                let _ = tokio::task::spawn_blocking(move || {
                    Accounts::update(&path, |a| a.refund(&token, n, day))
                })
                .await;
                (400, refusal("a blinded message is not one"))
            }
        }
    }

    fn records(&self) -> String {
        let keys: Vec<&PassKeyRecord> = self.keys.iter().map(|(_, r)| r).collect();
        serde_json::json!({ "keys": keys }).to_string()
    }
}

async fn serve(issuer: Arc<Issuer>, listen: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    info!(
        "pass issuer on TCP {} with {} key(s)",
        listen.port(),
        issuer.keys.len()
    );
    let slots = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let Ok(slot) = slots.clone().acquire_owned().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let (mut stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!("accept: {e}; waiting");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let issuer = issuer.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tokio::time::timeout(PER_CONNECTION, async move {
                let (status, body) = match read_request(&mut stream).await {
                    Err(_) => (400, refusal("not a request this service reads")),
                    Ok(req) => match (req.method.as_str(), req.path.as_str()) {
                        ("POST", "/issue") => issuer.issue(&req.body).await,
                        ("GET", "/") | ("GET", "/keys") => (200, issuer.records()),
                        ("GET", _) | ("POST", _) => (404, refusal("no such path")),
                        _ => (405, refusal("GET or POST")),
                    },
                };
                let _ = stream.write_all(&http_response(status, &body)).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            })
            .await;
        });
    }
}

/// A blinded message has the size of the key's modulus, in base64.
fn looks_blinded(b64: &str) -> bool {
    use base64::engine::general_purpose::STANDARD;
    STANDARD
        .decode(b64.trim())
        .map(|b| b.len() == hidravpn_core::pass::KEY_BITS / 8)
        .unwrap_or(false)
}

fn is_loopback(a: &SocketAddr) -> bool {
    a.ip().is_loopback()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hidravpn_issuer=info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out, days } => {
            if out.exists() {
                return Err(anyhow!("{} exists; not overwriting a key", out.display()));
            }
            if !(1..=400).contains(&days) {
                return Err(anyhow!("--days is 1 to 400"));
            }
            let secret = IssuerSecret::generate()?;
            let record = PassKeyRecord {
                id: secret.public().id_hex(),
                key: secret.public().to_spki_base64(),
                not_after: rfc3339(
                    hidravpn_core::timefmt::now_unix() + i64::from(days) * 86_400 + 86_400,
                ),
            };
            let file = KeyFile {
                secret: secret.to_der_base64()?,
                record: record.clone(),
            };
            write_private(&out, serde_json::to_string_pretty(&file)?.as_bytes(), true)?;
            eprintln!(
                "issuer key written to {} — it signs passes; keep it on the issuer only",
                out.display()
            );
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        Cmd::Record { key } => {
            let (_, record) = load_key(&key)?;
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        Cmd::Account { what } => {
            // Every change goes through the lock the running issuer takes.
            let path = cli.accounts.clone();
            match what {
                Account::Add { name, quota } => {
                    let token = Accounts::update(&path, |a| a.add(&name, quota))??;
                    eprintln!(
                        "account {} added, {quota} passes a day. Its token, shown this once (only its hash is kept):",
                        name.trim()
                    );
                    println!("{token}");
                }
                Account::List => {
                    let a = Accounts::load(&path)?;
                    for e in &a.accounts {
                        let used = if e.day == today() { e.used } else { 0 };
                        println!(
                            "{:<32} {:>6}/day  {:>6} used today  {}",
                            e.name,
                            e.quota_per_day,
                            used,
                            if e.enabled { "on" } else { "OFF" }
                        );
                    }
                    if a.accounts.is_empty() {
                        println!("(no accounts)");
                    }
                }
                Account::Disable { name } => {
                    Accounts::update(&path, |a| a.set_enabled(&name, false))??;
                    println!("{name}: off");
                }
                Account::Enable { name } => {
                    Accounts::update(&path, |a| a.set_enabled(&name, true))??;
                    println!("{name}: on");
                }
            }
        }
        Cmd::Run {
            keys,
            listen,
            plain_http_public,
        } => {
            if !is_loopback(&listen) && !plain_http_public {
                return Err(anyhow!(
                    "{listen} is not a loopback address: tokens would cross the network in the clear. Put a TLS proxy in front and listen on 127.0.0.1, or pass --plain-http-public on a private network"
                ));
            }
            let mut loaded = Vec::new();
            for k in &keys {
                loaded.push(load_key(k)?);
            }
            Accounts::load(&cli.accounts)?;
            let issuer = Arc::new(Issuer {
                keys: loaded,
                accounts_path: cli.accounts.clone(),
                lock: Mutex::new(()),
            });
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                r = serve(issuer, listen) => r?,
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            info!("stopping");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_gets_its_quota_a_day_and_not_one_more() {
        let mut a = Accounts::default();
        let t = a.add("alice", 5).unwrap();
        assert!(a.add("alice", 5).is_err(), "names are unique");
        assert!(a.add("has space", 5).is_err());
        assert_eq!(a.charge(&t, 3, 100), Ok(2));
        assert_eq!(a.charge(&t, 3, 100), Err(Refused::Quota { left: 2 }));
        assert_eq!(a.charge(&t, 2, 100), Ok(0));
        assert_eq!(a.charge(&t, 1, 100), Err(Refused::Quota { left: 0 }));
        assert_eq!(a.charge(&t, 1, 101), Ok(4), "a new day, a new quota");
        assert_eq!(a.charge("not-a-token", 1, 101), Err(Refused::UnknownToken));
        a.set_enabled("alice", false).unwrap();
        assert_eq!(a.charge(&t, 1, 101), Err(Refused::Disabled));
        // The file holds the token's hash, never the token.
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains(&t));
        assert!(json.contains(&token_hash(&t)));
    }

    #[test]
    fn changes_made_at_once_from_many_places_are_all_kept() {
        let dir = std::env::temp_dir().join(format!("hidravpn-issuer-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.json");
        let _ = std::fs::remove_file(&path);
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    Accounts::update(&path, |a| a.add(&format!("acct-{i}"), 1))
                        .unwrap()
                        .unwrap()
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            Accounts::load(&path).unwrap().accounts.len(),
            8,
            "no change was lost"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dates_come_out_as_the_lists_write_them() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_868_800), "2000-03-01T00:00:00Z");
        assert_eq!(rfc3339(1_791_894_896), "2026-10-13T00:00:00Z");
        for t in [0i64, 951_868_800, 1_791_849_600, 4_102_444_800] {
            assert_eq!(
                hidravpn_core::timefmt::rfc3339_to_unix(&rfc3339(t)).unwrap(),
                t.div_euclid(86_400) * 86_400
            );
        }
    }

    #[tokio::test]
    async fn the_issuer_signs_for_an_account_and_refuses_the_rest() {
        let dir = std::env::temp_dir().join(format!("hidravpn-issuer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let accounts_path = dir.join("accounts.json");
        let mut a = Accounts::default();
        let token = a.add("bob", 2).unwrap();
        a.save(&accounts_path).unwrap();
        let secret = IssuerSecret::generate().unwrap();
        let record = PassKeyRecord {
            id: secret.public().id_hex(),
            key: secret.public().to_spki_base64(),
            not_after: "2100-01-01T00:00:00Z".into(),
        };
        let issuer = Arc::new(Issuer {
            keys: vec![(secret, record.clone())],
            accounts_path: accounts_path.clone(),
            lock: Mutex::new(()),
        });
        let node = hidravpn_core::ClientKey::generate()
            .unwrap()
            .public_base64();
        let key = record.issuer_key().unwrap();
        let ask = |token: &str, n: usize| {
            let mut pending = Vec::new();
            let mut blinded = Vec::new();
            for _ in 0..n {
                let (b, p) = hidravpn_core::pass::prepare(&key, &node).unwrap();
                blinded.push(b);
                pending.push(p);
            }
            let body = serde_json::to_vec(&IssueRequest {
                token: token.into(),
                key_id: record.id.clone(),
                blinded,
            })
            .unwrap();
            (body, pending)
        };
        let (body, pending) = ask(&token, 2);
        let (status, answer) = issuer.issue(&body).await;
        assert_eq!(status, 200, "{answer}");
        let resp: IssueResponse = serde_json::from_str(&answer).unwrap();
        assert_eq!(resp.remaining_today, 0);
        let trusted = [record.clone()];
        let now = hidravpn_core::timefmt::now_unix();
        for (p, sig) in pending.into_iter().zip(resp.signatures) {
            let pass = p.finalize(&key, &sig).unwrap();
            pass.redemption()
                .unwrap()
                .verify(&trusted, &node, now)
                .unwrap();
        }
        // The quota is written down, so it holds across a restart.
        let (body, _) = ask(&token, 1);
        assert_eq!(issuer.issue(&body).await.0, 429);
        let (body, _) = ask("wrong", 1);
        assert_eq!(
            issuer.issue(&body).await.0,
            403,
            "no account: refused before anything is signed"
        );
        // A message of the right size but not base64, or of the wrong size:
        // refused before the account is charged.
        let mut bad = serde_json::from_slice::<IssueRequest>(&ask(&token, 1).0).unwrap();
        bad.blinded = vec!["AAAA".into()];
        assert_eq!(
            issuer.issue(&serde_json::to_vec(&bad).unwrap()).await.0,
            400
        );
        let (status, _) = issuer.issue(b"{ not json").await;
        assert_eq!(status, 400);
        let (body, _) = ask(&token, MAX_PER_REQUEST + 1);
        assert_eq!(issuer.issue(&body).await.0, 400);
        let mut wrong_key = serde_json::from_slice::<IssueRequest>(&ask(&token, 1).0).unwrap();
        wrong_key.key_id = "0011223344556677".into();
        assert_eq!(
            issuer
                .issue(&serde_json::to_vec(&wrong_key).unwrap())
                .await
                .0,
            400
        );
        assert!(issuer.records().contains(&record.id));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
