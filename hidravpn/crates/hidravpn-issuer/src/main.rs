//! The HidraVPN pass issuer (phase 5).
//!
//!   hidravpn-issuer keygen --out issuer-key.json [--days 35]   a new signing key; prints its record
//!   hidravpn-issuer record --key issuer-key.json               the record again, for the list and the nodes
//!   hidravpn-issuer account add --name NAME --quota N          a new account; prints its token once
//!   hidravpn-issuer account add --name NAME --prepaid N        one with N passes in all, no daily quota
//!   hidravpn-issuer account list | disable NAME | enable NAME
//!   hidravpn-issuer run --key issuer-key.json [--key ...]      serve POST /issue
//!       [--pay-wallet ADDR --pay-pack PASSES=PRICE ...]         and sell passes for HNET (phase 7)
//!
//! What it does: an account that is enabled and under its daily quota (or
//! with passes left, for a prepaid one) sends blinded pass messages and gets
//! them back signed. It never sees what it signs, so it never learns which
//! node a pass is for, nor the key a pass admits; a node that takes the pass
//! never learns which account it came from. What it keeps: its key, and per
//! account a name, the SHA-256 of the token (never the token), the quota and
//! today's count, or the balance. It logs counts, never an account, a token
//! or an address.
//!
//! With `--pay-wallet` and packs it also sells passes: `POST /quote` opens an
//! order (an exact amount of HNET to send), `POST /claim` names the
//! transaction that paid it, and the issuer, once it has seen the payment
//! finalized on chain, credits the pack to the account the token names
//! (`hidravpn_core::payment` says how, and what is never logged or kept).
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
use hidravpn_core::payment::{
    self, ClaimRequest, ClaimResponse, Pack, PackSpec, PacksResponse, QuoteRequest, QuoteResponse,
    Rejected, CLOCK_SLACK, ORDER_LIFETIME,
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
    /// The orders file (passes sold for HNET).
    #[arg(
        long,
        global = true,
        default_value = "/var/lib/hidravpn-issuer/orders.json"
    )]
    orders: PathBuf,
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
        /// Sell passes for HNET sent to this Solana wallet (its public
        /// address; the issuer holds no key for it). Needs --pay-pack.
        #[arg(long)]
        pay_wallet: Option<String>,
        /// A pack for sale, PASSES=PRICE, the price in whole HNET
        /// (`--pay-pack 10=50`) or in dollars, turned into HNET at the
        /// going rate (`--pay-pack 150=5.99usd`). Give as many as there
        /// are packs.
        #[arg(long = "pay-pack")]
        pay_packs: Vec<String>,
        /// Where the going rate comes from, for packs priced in dollars: a
        /// DEX screener's answer about the mint (by default,
        /// api.dexscreener.com's for it). Give it more than once for
        /// redundancy: each refresh tries them in order and takes the
        /// first that answers, so one feed being down does not stop
        /// dollar-priced sales. Each must speak the same shape.
        #[arg(long = "pay-price-url")]
        pay_price_urls: Vec<String>,
        /// How often the rate is fetched, in seconds.
        #[arg(long, default_value_t = 300)]
        pay_price_every: u64,
        /// A rate older than this many seconds is not used: dollar-priced
        /// packs are then not for sale until the feed answers again.
        #[arg(long, default_value_t = 3600)]
        pay_price_max_age: u64,
        /// A rate that moved more than this many percent since the last
        /// one is held back until three fetches in a row agree on it.
        #[arg(long, default_value_t = 30)]
        pay_price_max_change: u32,
        /// The token's mint address (HNET's by default).
        #[arg(long, default_value = payment::HNET_MINT)]
        pay_mint: String,
        /// The token's decimals (HNET: 6).
        #[arg(long, default_value_t = payment::HNET_DECIMALS)]
        pay_decimals: u8,
        /// A Solana JSON-RPC endpoint payments are looked up at. Give it
        /// more than once to cross-check across several independent RPCs:
        /// a claim is credited only when a strict majority of them read
        /// the same payment, so one lying or faulty RPC cannot conjure a
        /// payment out of nothing. Defaults to one public mainnet RPC;
        /// for real money, run three or more.
        #[arg(long = "pay-rpc")]
        pay_rpc: Vec<String>,
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
        /// Instead of a daily quota: this many passes in all, as a purchase
        /// gives. `hidravpn passes buy` tops such an account up.
        #[arg(long, conflicts_with = "quota")]
        prepaid: Option<u32>,
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
    /// A prepaid account: how many passes it has left in all. Set by a
    /// purchase or `account add --prepaid`; such an account has no daily
    /// quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    balance: Option<u32>,
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
    Quota {
        left: u32,
    },
    /// A prepaid account with too few passes left.
    Balance {
        left: u32,
    },
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
    /// other's change. The lock is held only for the time of `f`. Nothing is
    /// written when `f` changed nothing: a request with a token nobody issued
    /// costs a read, never a write to disk.
    fn update<T>(path: &Path, f: impl FnOnce(&mut Accounts) -> T) -> Result<T> {
        let _held = lock_file(path)?;
        let mut a = Accounts::load(path)?;
        let before = serde_json::to_vec(&a)?;
        let out = f(&mut a);
        if serde_json::to_vec(&a)? != before {
            a.save(path)?;
        }
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

    fn add(&mut self, name: &str, quota: u32, prepaid: Option<u32>) -> Result<String> {
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
            quota_per_day: if prepaid.is_some() { 0 } else { quota },
            enabled: true,
            day: 0,
            used: 0,
            balance: prepaid,
        });
        Ok(token)
    }

    /// Credits `passes` to the account whose token hashes to `hash`, making
    /// a prepaid one if there is none; an account with a daily quota that
    /// buys becomes prepaid. Returns the balance now.
    fn credit(&mut self, hash: &str, passes: u32) -> Result<u32> {
        if let Some(a) = self
            .accounts
            .iter_mut()
            .find(|a| same(a.token_sha256.as_bytes(), hash.as_bytes()))
        {
            let b = a.balance.unwrap_or(0).saturating_add(passes);
            a.balance = Some(b);
            return Ok(b);
        }
        // Named after nothing: the name must not say when or by whom.
        let mut raw = [0u8; 4];
        getrandom::fill(&mut raw).map_err(|e| anyhow!("no randomness available: {e}"))?;
        let mut name = format!("paid-{}", hex::encode(raw));
        while self.accounts.iter().any(|a| a.name == name) {
            name.push('x');
        }
        self.accounts.push(AccountEntry {
            name,
            token_sha256: hash.to_string(),
            quota_per_day: 0,
            enabled: true,
            day: 0,
            used: 0,
            balance: Some(passes),
        });
        Ok(passes)
    }

    /// A prepaid account's balance; None for no such account or one with a
    /// daily quota.
    fn balance_of(&self, hash: &str) -> Option<u32> {
        self.accounts
            .iter()
            .find(|a| same(a.token_sha256.as_bytes(), hash.as_bytes()))
            .and_then(|a| a.balance)
    }

    /// Gives back `n` passes counted today and never signed.
    fn refund(&mut self, token: &str, n: u32, today: i64) {
        let h = token_hash(token);
        if let Some(a) = self
            .accounts
            .iter_mut()
            .find(|a| same(a.token_sha256.as_bytes(), h.as_bytes()))
        {
            if let Some(b) = a.balance {
                a.balance = Some(b.saturating_add(n));
            } else if a.day == today {
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

    /// Counts `n` passes against the account the token names — today's
    /// quota, or a prepaid balance — if it may have them; all or nothing.
    /// Returns how many it has left (today, or in all), and whether it is
    /// prepaid.
    fn charge(
        &mut self,
        token: &str,
        n: u32,
        today: i64,
    ) -> std::result::Result<(u32, bool), Refused> {
        let h = token_hash(token);
        let a = self
            .accounts
            .iter_mut()
            .find(|a| same(a.token_sha256.as_bytes(), h.as_bytes()))
            .ok_or(Refused::UnknownToken)?;
        if !a.enabled {
            return Err(Refused::Disabled);
        }
        if let Some(b) = a.balance {
            if n > b {
                return Err(Refused::Balance { left: b });
            }
            a.balance = Some(b - n);
            return Ok((b - n, true));
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
        Ok((left - n, false))
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
    /// Passes for sale, or not.
    payments: Option<Payments>,
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
        let (left, prepaid) = match charged {
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
            Ok(Ok(Err(Refused::Balance { left }))) => {
                return (
                    402,
                    refusal(format!(
                        "this account has {left} pass(es) left, not {n}; `hidravpn passes buy` adds more"
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
                    prepaid,
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

    fn packs(&self) -> (u16, String) {
        match &self.payments {
            None => (404, refusal("this issuer does not sell passes")),
            Some(p) => {
                let rate = p.rate_now();
                (
                    200,
                    serde_json::to_string(&PacksResponse {
                        packs: p.packs_at(rate),
                        decimals: p.decimals,
                        mint: p.mint.clone(),
                        wallet: p.wallet.clone(),
                        token_name: p.token_name.clone(),
                        rate: rate.map(payment::rate_to_string),
                    })
                    .expect("an answer serialises"),
                )
            }
        }
    }

    /// `POST /quote`: opens an order for a pack.
    async fn quote(self: &Arc<Self>, body: &[u8]) -> (u16, String) {
        let Some(p) = &self.payments else {
            return (404, refusal("this issuer does not sell passes"));
        };
        let req: QuoteRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => {
                return (
                    400,
                    refusal("the request is not {\"token_sha256\", \"passes\"}"),
                )
            }
        };
        if req.token_sha256.len() != 64 || !req.token_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return (400, refusal("token_sha256 is the token's SHA-256, in hex"));
        }
        let Some(spec) = p.specs.iter().find(|k| k.passes == req.passes) else {
            return (
                400,
                refusal(format!(
                    "no pack of {} passes; the packs are: {}",
                    req.passes,
                    p.specs
                        .iter()
                        .map(|k| match k.price {
                            payment::Price::Usd(cents) =>
                                format!("{} for {} USD", k.passes, payment::usd_to_string(cents)),
                            payment::Price::Tokens(raw) => format!(
                                "{} for {} {}",
                                k.passes,
                                payment::amount_to_string(raw, p.decimals)
                                    .trim_end_matches('0')
                                    .trim_end_matches('.'),
                                if p.token_name.is_empty() {
                                    "tokens"
                                } else {
                                    &p.token_name
                                }
                            ),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            );
        };
        // A pack priced in dollars is sold at the going rate, and not at
        // all while the rate is unknown or stale.
        let rate = p.rate_now();
        let Some(pack) = spec.at(rate, p.decimals) else {
            return (
                503,
                refusal("the token's going rate is not known right now, so this pack is not for sale; try again in a few minutes"),
            );
        };
        if !p.quotes.take().await {
            return (
                429,
                refusal("too many orders at once; try again in a moment"),
            );
        }
        let hash = req.token_sha256.to_ascii_lowercase();
        let now = hidravpn_core::timefmt::now_unix();
        let path = p.orders_path.clone();
        let decimals = p.decimals;
        let opened = {
            let _one_at_a_time = self.lock.lock().await;
            let pack = pack.clone();
            tokio::task::spawn_blocking(move || {
                Orders::update(&path, |o| o.open(&hash, &pack, now, decimals))
            })
            .await
        };
        match opened {
            Ok(Ok(Ok(order))) => {
                info!("order opened for {} pass(es)", order.passes);
                (
                    200,
                    serde_json::to_string(&QuoteResponse {
                        passes: order.passes,
                        amount: payment::amount_to_string(order.amount_raw, p.decimals),
                        amount_raw: order.amount_raw,
                        decimals: p.decimals,
                        mint: p.mint.clone(),
                        wallet: p.wallet.clone(),
                        expires: rfc3339_full(order.created + ORDER_LIFETIME),
                        usd: pack.usd_cents.map(payment::usd_to_string),
                        rate: pack.usd_cents.and(rate).map(payment::rate_to_string),
                    })
                    .expect("an answer serialises"),
                )
            }
            Ok(Ok(Err(Full::Issuer))) => (
                503,
                refusal("the issuer has as many orders open as it takes; try again later"),
            ),
            Ok(Ok(Err(Full::Account))) => (
                429,
                refusal(format!(
                    "this account already has {MAX_OPEN_PER_ACCOUNT} orders open; pay and claim one, or wait for them to lapse"
                )),
            ),
            Ok(Err(e)) => {
                warn!("orders: {e:#}");
                (503, refusal("the issuer cannot read or write its orders"))
            }
            Err(_) => (503, refusal("the issuer could not open the order")),
        }
    }

    /// `POST /claim`: a transaction that paid one of the token's orders.
    async fn claim(self: &Arc<Self>, body: &[u8]) -> (u16, String) {
        let Some(p) = &self.payments else {
            return (404, refusal("this issuer does not sell passes"));
        };
        let req: ClaimRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => {
                return (
                    400,
                    refusal("the request is not {\"token\", \"signature\"}"),
                )
            }
        };
        let token = req.token.trim();
        if token.is_empty() || token.len() > 512 || token.chars().any(char::is_whitespace) {
            return (400, refusal("that is not an account token"));
        }
        let signature = match payment::check_signature(&req.signature) {
            Ok(s) => s,
            Err(e) => return (400, refusal(format!("{e:#}"))),
        };
        if !p.claims.take().await {
            return (
                429,
                refusal("too many claims at once; try again in a moment"),
            );
        }
        let hash = token_hash(token);
        let sig_hash = hex::encode(Sha256::digest(signature.as_bytes()));
        let now = hidravpn_core::timefmt::now_unix();
        // Before the chain is asked: is there an order to pay, was this
        // transaction already used, has this order been tried too often?
        let path = p.orders_path.clone();
        let (hash2, sig2) = (hash.clone(), sig_hash.clone());
        let before = {
            let _one_at_a_time = self.lock.lock().await;
            tokio::task::spawn_blocking(move || {
                Orders::update(&path, |o| o.before_claim(&hash2, &sig2, now))
            })
            .await
        };
        let candidates = match before {
            Ok(Ok(Ok(Claimable::Open(c)))) => c,
            Ok(Ok(Ok(Claimable::AlreadyPaid { passes, amount_raw }))) => {
                // The same transaction paid this order before: say so, with
                // the balance as it stands. Nothing is credited twice.
                let path = self.accounts_path.clone();
                let hash = hash.clone();
                let balance = tokio::task::spawn_blocking(move || {
                    Accounts::load(&path).map(|a| a.balance_of(&hash).unwrap_or(0))
                })
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
                return (
                    200,
                    serde_json::to_string(&ClaimResponse {
                        passes,
                        balance,
                        amount_raw,
                        already_claimed: true,
                    })
                    .expect("an answer serialises"),
                );
            }
            Ok(Ok(Err(NotClaimable::NoOrder))) => {
                return (
                    404,
                    refusal("no open order for this token (none made, or it lapsed after 24 hours); `hidravpn passes buy` makes one"),
                )
            }
            Ok(Ok(Err(NotClaimable::Used))) => {
                return (409, refusal("that transaction already paid an order"))
            }
            Ok(Ok(Err(NotClaimable::TooManyTries))) => {
                return (
                    429,
                    refusal("this order was tried too many times; make a new one with `hidravpn passes buy`"),
                )
            }
            Ok(Err(e)) => {
                warn!("orders: {e:#}");
                return (503, refusal("the issuer cannot read or write its orders"));
            }
            Err(_) => return (503, refusal("the issuer could not read its orders")),
        };
        // The chain, a few claims at a time. One claim crosses every RPC
        // and is credited only on a strict majority reading the same
        // payment, so no single RPC — lying or broken — decides it.
        let paid = {
            let Ok(_slot) = p.rpc_slots.acquire().await else {
                return (503, refusal("the issuer cannot ask the chain right now"));
            };
            match p.confirm(&signature).await {
                Quorum::Paid(paid) => paid,
                Quorum::Refused(why) => {
                    warn!("claim refused: {}", why.kind());
                    return (
                        match why {
                            Rejected::NotFound => 404,
                            Rejected::Malformed => 503,
                            _ => 402,
                        },
                        refusal(why.to_string()),
                    );
                }
                Quorum::Undecided => {
                    warn!("claim refused: the chain's RPCs did not agree");
                    return (
                        503,
                        refusal("the issuer could not confirm this payment on the chain right now; its RPCs did not agree. Try the claim again shortly"),
                    );
                }
            }
        };
        // Which of the token's open orders did it pay? The exact amount,
        // and the order made before the payment.
        let Some(order) = candidates
            .iter()
            .find(|o| paid.pays(o.amount_raw, o.created).is_ok())
            .cloned()
        else {
            let why = candidates
                .iter()
                .map(|o| paid.pays(o.amount_raw, o.created).unwrap_err())
                .find(|w| matches!(w, Rejected::WrongAmount { .. }))
                .unwrap_or(Rejected::TooEarly);
            warn!("claim refused: {}", why.kind());
            return (402, refusal(why.to_string()));
        };
        // Under the issuer's lock again: the order is marked paid and the
        // transaction used (another claim with the same transaction
        // meanwhile is now refused), then the account is credited. Each
        // file under its own lock, one after the other: the issuer's lock
        // keeps its own claims and issuances apart, and an `account`
        // command run meanwhile touches the accounts file only.
        let (path_o, path_a) = (p.orders_path.clone(), self.accounts_path.clone());
        let (hash2, sig2, amount) = (hash.clone(), sig_hash.clone(), order.amount_raw);
        let credited = {
            let _one_at_a_time = self.lock.lock().await;
            tokio::task::spawn_blocking(
                move || -> Result<std::result::Result<u32, NotClaimable>> {
                    let marked =
                        Orders::update(&path_o, |o| o.mark_paid(&hash2, amount, &sig2, now))?;
                    if let Err(e) = marked {
                        return Ok(Err(e));
                    }
                    match Accounts::update(&path_a, |a| a.credit(&hash2, order.passes)) {
                        Ok(Ok(b)) => Ok(Ok(b)),
                        Ok(Err(e)) | Err(e) => {
                            // Credited nothing: the order goes back to open, so
                            // the claim can be made again.
                            let _ = Orders::update(&path_o, |o| o.unmark(&hash2, amount, &sig2));
                            Err(e)
                        }
                    }
                },
            )
            .await
        };
        match credited {
            Ok(Ok(Ok(balance))) => {
                info!("order claimed: {} pass(es) credited", order.passes);
                (
                    200,
                    serde_json::to_string(&ClaimResponse {
                        passes: order.passes,
                        balance,
                        amount_raw: order.amount_raw,
                        already_claimed: false,
                    })
                    .expect("an answer serialises"),
                )
            }
            Ok(Ok(Err(NotClaimable::Used))) => {
                (409, refusal("that transaction already paid an order"))
            }
            Ok(Ok(Err(_))) => (
                404,
                refusal("no open order for this token any more; `hidravpn passes buy` makes one"),
            ),
            Ok(Err(e)) => {
                warn!("crediting: {e:#}");
                (
                    503,
                    refusal("the issuer could not credit the account; try the claim again"),
                )
            }
            Err(_) => (
                503,
                refusal("the issuer could not credit the account; try the claim again"),
            ),
        }
    }
}

// ---- passes for sale ---------------------------------------------------------------

/// Orders open at once, in all; past it a quote is refused until some lapse.
const MAX_OPEN_ORDERS: usize = 20_000;
/// Orders open at once for one token.
const MAX_OPEN_PER_ACCOUNT: usize = 5;
/// Claims tried on one token's open orders before a new order is needed:
/// each try is a lookup on the chain.
const MAX_CLAIM_TRIES: u32 = 30;
/// Lookups on the chain at once. A single claim's quorum (one lookup per
/// RPC, in turn) holds one slot for its whole run, so this bounds how many
/// claims reach the chain at a time, not how many RPCs one claim crosses.
const RPC_AT_ONCE: usize = 4;
/// The one public RPC used when the operator names none.
const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

/// What the issuer sells and where payments go.
struct Payments {
    wallet: String,
    mint: String,
    decimals: u8,
    /// The RPCs a payment is cross-checked against. One claim asks each in
    /// turn and credits only on a strict majority agreeing.
    rpcs: Vec<hidravpn_core::http::Url>,
    specs: Vec<PackSpec>,
    /// The going rate, for packs priced in dollars; None with none such.
    rate: Option<Rate>,
    token_name: String,
    orders_path: PathBuf,
    rpc_slots: Semaphore,
    /// Quotes and claims are each let through at a steady rate with a small
    /// burst: a flood opens no more orders, and asks the chain no more
    /// often, than that.
    quotes: Bucket,
    claims: Bucket,
}

/// A lookup on the chain that did not answer: a word for the log, a line
/// for the client.
struct LookupFailed {
    kind: &'static str,
    shown: String,
}

impl Payments {
    fn new(
        wallet: &str,
        mint: &str,
        decimals: u8,
        rpcs: &[String],
        packs: &[String],
        feed: Option<RateFeed>,
        orders_path: PathBuf,
    ) -> Result<Payments> {
        let wallet = payment::check_address(wallet).context("--pay-wallet")?;
        let mint = payment::check_address(mint).context("--pay-mint")?;
        if wallet == mint {
            return Err(anyhow!(
                "--pay-wallet is the mint itself; payments go to a wallet"
            ));
        }
        if decimals > 12 {
            return Err(anyhow!("--pay-decimals is 0 to 12"));
        }
        let mut rpcs_parsed = Vec::new();
        let default_rpc = [String::from(DEFAULT_RPC)];
        let given: &[String] = if rpcs.is_empty() { &default_rpc } else { rpcs };
        for r in given {
            rpcs_parsed.push(hidravpn_core::http::Url::parse(r).context("--pay-rpc")?);
        }
        let mut parsed: Vec<PackSpec> = Vec::new();
        for p in packs {
            let pack = PackSpec::parse(p, decimals).context("--pay-pack")?;
            if parsed.iter().any(|k| k.passes == pack.passes) {
                return Err(anyhow!("--pay-pack: two packs of {} passes", pack.passes));
            }
            parsed.push(pack);
        }
        parsed.sort_by_key(|k| k.passes);
        let in_dollars = parsed
            .iter()
            .any(|k| matches!(k.price, payment::Price::Usd(_)));
        let rate = match (in_dollars, feed) {
            (false, _) => None,
            (true, Some(f)) => Some(Rate::new(f, &mint)?),
            (true, None) => {
                return Err(anyhow!(
                    "a pack priced in dollars needs the going rate: --pay-price-url, or the default feed"
                ))
            }
        };
        Ok(Payments {
            wallet,
            token_name: if mint == payment::HNET_MINT {
                "HNET".into()
            } else {
                String::new()
            },
            mint,
            decimals,
            rpcs: rpcs_parsed,
            specs: parsed,
            rate,
            orders_path,
            rpc_slots: Semaphore::new(RPC_AT_ONCE),
            quotes: Bucket::new(30.0, 3.0),
            claims: Bucket::new(20.0, 2.0),
        })
    }

    /// The going rate, if it is known and fresh.
    fn rate_now(&self) -> Option<f64> {
        self.rate
            .as_ref()
            .and_then(|r| r.current(hidravpn_core::timefmt::now_unix()))
    }

    /// The packs at a rate: the ones priced in dollars only with one.
    fn packs_at(&self, rate: Option<f64>) -> Vec<Pack> {
        self.specs
            .iter()
            .filter_map(|k| k.at(rate, self.decimals))
            .collect()
    }

    /// The wallet and token a payment to this issuer must reach.
    fn receiver(&self) -> payment::Receiver<'_> {
        payment::Receiver {
            wallet: &self.wallet,
            mint: &self.mint,
            decimals: self.decimals,
        }
    }

    /// Fetches a transaction from one RPC, finalized, as
    /// `payment::inspect_payment` reads it. Only the JSON-RPC `result`; an
    /// RPC error is a failure.
    async fn fetch_transaction(
        &self,
        url: &hidravpn_core::http::Url,
        signature: &str,
    ) -> std::result::Result<serde_json::Value, LookupFailed> {
        let body = payment::get_transaction_request(signature);
        let (status, answer) = hidravpn_core::http::call(url, "POST", &body)
            .await
            .map_err(|e| LookupFailed {
                kind: "no-answer",
                shown: format!("{e:#}"),
            })?;
        if status != 200 {
            return Err(LookupFailed {
                kind: "http-status",
                shown: format!("the chain's RPC answered {status}"),
            });
        }
        let v: serde_json::Value = serde_json::from_str(&answer).map_err(|_| LookupFailed {
            kind: "not-json",
            shown: "the chain's RPC answer is not JSON".into(),
        })?;
        if let Some(e) = v.get("error") {
            let msg = e
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("an error without a message")
                .chars()
                .take(120)
                .collect::<String>();
            return Err(LookupFailed {
                kind: "rpc-error",
                shown: format!("the chain's RPC refused: {msg}"),
            });
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    /// Asks one RPC and reads its answer into a verdict. An RPC that does
    /// not answer, or answers unreadably, is `Unreachable` — it neither
    /// confirms nor denies.
    async fn verdict_of(&self, url: &hidravpn_core::http::Url, signature: &str) -> Verdict {
        match self.fetch_transaction(url, signature).await {
            Ok(result) => match payment::inspect_payment(&result, &self.receiver()) {
                Ok(paid) => Verdict::Paid(paid),
                Err(why) => Verdict::Rejected(why),
            },
            Err(e) => {
                warn!("chain lookup failed on one RPC ({}): {}", e.kind, e.shown);
                Verdict::Unreachable
            }
        }
    }

    /// Asks every RPC in turn and takes the quorum of their answers: a
    /// payment is confirmed only if a strict majority read the very same
    /// one. One lying RPC in a set of three cannot pass a payment off, nor
    /// can one that is merely broken; a single RPC is its own majority, so
    /// a one-RPC issuer behaves as before.
    async fn confirm(&self, signature: &str) -> Quorum {
        let mut verdicts = Vec::with_capacity(self.rpcs.len());
        for url in &self.rpcs {
            verdicts.push(self.verdict_of(url, signature).await);
        }
        tally(&verdicts, self.rpcs.len())
    }
}

/// What one RPC said about a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// It answered, and the answer reads as this payment.
    Paid(payment::Payment),
    /// It answered, and the answer is no payment, for this reason.
    Rejected(payment::Rejected),
    /// It did not answer, or not readably.
    Unreachable,
}

/// What a set of RPC answers says, taken together.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Quorum {
    /// A strict majority read the identical payment.
    Paid(payment::Payment),
    /// A strict majority rejected it the same way.
    Refused(payment::Rejected),
    /// Neither: too many RPCs unreachable, or they disagree.
    Undecided,
}

/// The quorum of `verdicts` over `total` RPCs. A strict majority
/// (`total / 2 + 1`) must agree, exactly, on a payment or on a rejection;
/// unreachable RPCs count toward neither, so they only ever withhold a
/// quorum, never forge one. Pure, so the agreement rule is tested on its
/// own.
fn tally(verdicts: &[Verdict], total: usize) -> Quorum {
    let need = total / 2 + 1;
    for v in verdicts {
        if let Verdict::Paid(p) = v {
            let agree = verdicts
                .iter()
                .filter(|o| matches!(o, Verdict::Paid(q) if q == p))
                .count();
            if agree >= need {
                return Quorum::Paid(*p);
            }
        }
    }
    for v in verdicts {
        if let Verdict::Rejected(r) = v {
            let agree = verdicts
                .iter()
                .filter(|o| matches!(o, Verdict::Rejected(q) if q == r))
                .count();
            if agree >= need {
                return Quorum::Refused(r.clone());
            }
        }
    }
    Quorum::Undecided
}

/// Where the going rate comes from and how it is trusted.
#[derive(Debug, Clone)]
struct RateFeed {
    /// One or more feeds of the same shape; a refresh takes the first that
    /// answers, so a feed being down does not stop dollar-priced sales.
    urls: Vec<String>,
    every: Duration,
    max_age: i64,
    /// A move of more than this fraction (0.3 for 30 %) is held back.
    max_change: f64,
}

/// The token's price in dollars, as the feed last said it, and a move too
/// large to take at once: a feed that lies or glitches sells nothing cheap
/// for a moment; one that moved for real is believed once it says so three
/// times in a row.
struct Rate {
    feed: RateFeed,
    urls: Vec<hidravpn_core::http::Url>,
    mint: String,
    state: std::sync::Mutex<RateState>,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct RateState {
    /// (dollars for one token, when it was fetched, unix)
    current: Option<(f64, i64)>,
    /// A move past the limit: the rate, and how many fetches in a row
    /// agreed with it.
    held: Option<(f64, u32)>,
}

/// Fetches in a row that must agree on a large move before it is taken.
const RATE_AGREE: u32 = 3;

impl Rate {
    fn new(feed: RateFeed, mint: &str) -> Result<Rate> {
        if feed.urls.is_empty() {
            return Err(anyhow!("a feed needs at least one --pay-price-url"));
        }
        let mut urls = Vec::with_capacity(feed.urls.len());
        for u in &feed.urls {
            urls.push(hidravpn_core::http::Url::parse(u).context("--pay-price-url")?);
        }
        if feed.max_age <= 0 || feed.every.is_zero() {
            return Err(anyhow!(
                "--pay-price-every and --pay-price-max-age are 1 or more"
            ));
        }
        Ok(Rate {
            feed,
            urls,
            mint: mint.to_string(),
            state: std::sync::Mutex::new(RateState::default()),
        })
    }

    /// The default feed for a mint.
    fn default_url(mint: &str) -> String {
        format!("https://api.dexscreener.com/tokens/v1/solana/{mint}")
    }

    /// The rate, if fetched within `max_age`.
    fn current(&self, now: i64) -> Option<f64> {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.current
            .filter(|&(_, at)| now - at <= self.feed.max_age)
            .map(|(r, _)| r)
    }

    /// Takes a freshly fetched rate in, or holds it: says which.
    fn offer(state: &mut RateState, new: f64, now: i64, max_change: f64) -> bool {
        let Some((cur, _)) = state.current else {
            state.current = Some((new, now));
            return true;
        };
        let moved = |from: f64| ((new / from) - 1.0).abs() > max_change;
        if !moved(cur) {
            state.current = Some((new, now));
            state.held = None;
            return true;
        }
        let agreed = match state.held {
            Some((held, n)) if !moved(held) => n + 1,
            _ => 1,
        };
        if agreed >= RATE_AGREE {
            state.current = Some((new, now));
            state.held = None;
            true
        } else {
            state.held = Some((new, agreed));
            false
        }
    }

    async fn refresh(&self) {
        // Each feed in turn; the first that answers with a usable rate
        // wins. A feed that is down or unreadable falls through to the
        // next, so one being out does not stall dollar-priced sales.
        let mut rate = Err(anyhow!("no price feed is configured"));
        for url in &self.urls {
            let fetched = hidravpn_core::http::call(url, "GET", "").await;
            rate = match fetched {
                Ok((200, body)) => payment::read_rate(&body, &self.mint),
                Ok((status, _)) => Err(anyhow!("the price feed answered {status}")),
                Err(e) => Err(e),
            };
            if rate.is_ok() {
                break;
            }
        }
        let now = hidravpn_core::timefmt::now_unix();
        match rate {
            Ok(r) => {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if Rate::offer(&mut s, r, now, self.feed.max_change) {
                    info!(
                        "going rate refreshed: {} USD for one token",
                        payment::rate_to_string(r)
                    );
                } else {
                    warn!(
                        "going rate moved more than {}% ({} USD for one token); held until the feed agrees {} times in a row",
                        (self.feed.max_change * 100.0).round(),
                        payment::rate_to_string(r),
                        RATE_AGREE
                    );
                }
            }
            Err(e) => warn!("the price feed did not answer: {e:#}"),
        }
    }
}

/// A token bucket: `rate` tokens a second, up to `burst` kept.
struct Bucket {
    state: Mutex<(f64, std::time::Instant)>,
    rate: f64,
    burst: f64,
}

impl Bucket {
    fn new(burst: f64, rate: f64) -> Bucket {
        Bucket {
            state: Mutex::new((burst, std::time::Instant::now())),
            rate,
            burst,
        }
    }

    /// Takes one if there is one.
    async fn take(&self) -> bool {
        let mut s = self.state.lock().await;
        let now = std::time::Instant::now();
        let (tokens, last) = *s;
        let tokens = (tokens + now.duration_since(last).as_secs_f64() * self.rate).min(self.burst);
        if tokens >= 1.0 {
            *s = (tokens - 1.0, now);
            true
        } else {
            *s = (tokens, now);
            false
        }
    }
}

/// One order: a pack to pay for, at an amount no other open order has.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Order {
    /// SHA-256 of the token the pack goes to, hex.
    token_sha256: String,
    passes: u32,
    amount_raw: u64,
    /// Unix time; the order can be paid and claimed for `ORDER_LIFETIME`.
    created: i64,
    /// SHA-256 of the signature of the transaction that paid it, once paid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paid_sha256: Option<String>,
    /// Claims tried on it.
    #[serde(default)]
    tries: u32,
}

impl Order {
    fn open_at(&self, now: i64) -> bool {
        self.paid_sha256.is_none() && now < self.created + ORDER_LIFETIME
    }
}

/// A transaction that paid, remembered so it pays only once.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Used {
    signature_sha256: String,
    at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Orders {
    #[serde(default)]
    orders: Vec<Order>,
    #[serde(default)]
    used: Vec<Used>,
}

#[derive(Debug, PartialEq)]
enum Full {
    Issuer,
    Account,
}

#[derive(Debug, PartialEq)]
enum Claimable {
    Open(Vec<Order>),
    AlreadyPaid { passes: u32, amount_raw: u64 },
}

#[derive(Debug, PartialEq)]
enum NotClaimable {
    NoOrder,
    Used,
    TooManyTries,
}

impl Orders {
    fn load(path: &Path) -> Result<Orders> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).context("the orders file is not valid"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Orders::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// As `Accounts::update`: under the file's lock, written only if changed.
    fn update<T>(path: &Path, f: impl FnOnce(&mut Orders) -> T) -> Result<T> {
        let _held = lock_file(path)?;
        let mut o = Orders::load(path)?;
        let before = serde_json::to_vec(&o)?;
        let out = f(&mut o);
        if serde_json::to_vec(&o)? != before {
            o.save(path)?;
        }
        Ok(out)
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
        write_private(&tmp, serde_json::to_string(self)?.as_bytes(), false)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Throws away what can no longer matter: orders that lapsed unpaid,
    /// paid ones and used transactions older than twice an order's life
    /// (the latest a transaction could still be claimed against another
    /// order is an order's life after it, plus the clock slack).
    fn prune(&mut self, now: i64) {
        let keep_paid = 2 * ORDER_LIFETIME + CLOCK_SLACK;
        self.orders.retain(|o| match o.paid_sha256 {
            None => now < o.created + ORDER_LIFETIME,
            Some(_) => now < o.created + keep_paid,
        });
        self.used.retain(|u| now < u.at + keep_paid);
    }

    fn open_count(&self, now: i64) -> usize {
        self.orders.iter().filter(|o| o.open_at(now)).count()
    }

    /// Opens an order for `pack`, at the pack's price plus a random tag no
    /// other open order has.
    fn open(
        &mut self,
        hash: &str,
        pack: &Pack,
        now: i64,
        decimals: u8,
    ) -> std::result::Result<Order, Full> {
        self.prune(now);
        if self.open_count(now) >= MAX_OPEN_ORDERS {
            return Err(Full::Issuer);
        }
        if self
            .orders
            .iter()
            .filter(|o| o.open_at(now) && same(o.token_sha256.as_bytes(), hash.as_bytes()))
            .count()
            >= MAX_OPEN_PER_ACCOUNT
        {
            return Err(Full::Account);
        }
        let space = payment::tag_space(decimals);
        for _ in 0..64 {
            let mut raw = [0u8; 8];
            if getrandom::fill(&mut raw).is_err() {
                return Err(Full::Issuer);
            }
            let tag = u64::from_le_bytes(raw) % space + 1;
            let amount_raw = pack.price_raw + tag;
            if self
                .orders
                .iter()
                .any(|o| o.open_at(now) && o.amount_raw == amount_raw)
            {
                continue;
            }
            let order = Order {
                token_sha256: hash.to_string(),
                passes: pack.passes,
                amount_raw,
                created: now,
                paid_sha256: None,
                tries: 0,
            };
            self.orders.push(order.clone());
            return Ok(order);
        }
        Err(Full::Issuer)
    }

    /// What a claim with this token and transaction may do, before the
    /// chain is asked: the token's open orders (each counted one try), or
    /// the order this very transaction paid already.
    fn before_claim(
        &mut self,
        hash: &str,
        sig_hash: &str,
        now: i64,
    ) -> std::result::Result<Claimable, NotClaimable> {
        self.prune(now);
        if let Some(o) = self.orders.iter().find(|o| {
            same(o.token_sha256.as_bytes(), hash.as_bytes())
                && o.paid_sha256
                    .as_deref()
                    .is_some_and(|p| same(p.as_bytes(), sig_hash.as_bytes()))
        }) {
            return Ok(Claimable::AlreadyPaid {
                passes: o.passes,
                amount_raw: o.amount_raw,
            });
        }
        if self
            .used
            .iter()
            .any(|u| same(u.signature_sha256.as_bytes(), sig_hash.as_bytes()))
        {
            return Err(NotClaimable::Used);
        }
        let mut open: Vec<Order> = Vec::new();
        for o in self
            .orders
            .iter_mut()
            .filter(|o| o.open_at(now) && same(o.token_sha256.as_bytes(), hash.as_bytes()))
        {
            o.tries = o.tries.saturating_add(1);
            open.push(o.clone());
        }
        if open.is_empty() {
            return Err(NotClaimable::NoOrder);
        }
        if open.iter().map(|o| o.tries).sum::<u32>() > MAX_CLAIM_TRIES {
            return Err(NotClaimable::TooManyTries);
        }
        Ok(Claimable::Open(open))
    }

    /// Marks the token's open order of `amount_raw` (no two open orders
    /// share an amount) paid by the transaction, and the transaction used.
    fn mark_paid(
        &mut self,
        hash: &str,
        amount_raw: u64,
        sig_hash: &str,
        now: i64,
    ) -> std::result::Result<(), NotClaimable> {
        if self
            .used
            .iter()
            .any(|u| same(u.signature_sha256.as_bytes(), sig_hash.as_bytes()))
        {
            return Err(NotClaimable::Used);
        }
        let o = self
            .orders
            .iter_mut()
            .find(|o| {
                o.open_at(now)
                    && o.amount_raw == amount_raw
                    && same(o.token_sha256.as_bytes(), hash.as_bytes())
            })
            .ok_or(NotClaimable::NoOrder)?;
        o.paid_sha256 = Some(sig_hash.to_string());
        self.used.push(Used {
            signature_sha256: sig_hash.to_string(),
            at: now,
        });
        Ok(())
    }

    /// Undoes `mark_paid` when the account could not be credited.
    fn unmark(&mut self, hash: &str, amount_raw: u64, sig_hash: &str) {
        if let Some(o) = self.orders.iter_mut().find(|o| {
            o.amount_raw == amount_raw
                && same(o.token_sha256.as_bytes(), hash.as_bytes())
                && o.paid_sha256.as_deref() == Some(sig_hash)
        }) {
            o.paid_sha256 = None;
        }
        self.used
            .retain(|u| !same(u.signature_sha256.as_bytes(), sig_hash.as_bytes()));
    }
}

/// A full RFC 3339 time, to the second.
fn rfc3339_full(unix: i64) -> String {
    let date = rfc3339(unix);
    let secs = unix.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        &date[..10],
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
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
            // The time limit is on the client: reading its request, and
            // later taking the answer. The signing in between is never cut
            // short: an account charged must get its passes.
            let req = match tokio::time::timeout(PER_CONNECTION, read_request(&mut stream)).await {
                Ok(Ok(req)) => Ok(req),
                Ok(Err(_)) => Err(()),
                Err(_) => return,
            };
            let (status, body) = match req {
                Err(()) => (400, refusal("not a request this service reads")),
                Ok(req) => match (req.method.as_str(), req.path.as_str()) {
                    // On a task of its own, so nothing can cut it between
                    // charging the account and signing, or giving the count
                    // back.
                    ("POST", "/issue") => {
                        let (issuer, body) = (issuer.clone(), req.body);
                        tokio::spawn(async move { issuer.issue(&body).await })
                            .await
                            .unwrap_or_else(|_| (503, refusal("the issuer could not answer")))
                    }
                    ("POST", "/quote") => issuer.quote(&req.body).await,
                    ("POST", "/claim") => {
                        let (issuer, body) = (issuer.clone(), req.body);
                        tokio::spawn(async move { issuer.claim(&body).await })
                            .await
                            .unwrap_or_else(|_| (503, refusal("the issuer could not answer")))
                    }
                    ("GET", "/packs") => issuer.packs(),
                    ("GET", "/") | ("GET", "/keys") => (200, issuer.records()),
                    ("GET", _) | ("POST", _) => (404, refusal("no such path")),
                    _ => (405, refusal("GET or POST")),
                },
            };
            let _ = tokio::time::timeout(PER_CONNECTION, async {
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
        // HidraVPN's own crates only, whatever RUST_LOG says, as the other
        // programs do.
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            hidravpn_core::logging::directives(
                std::env::var("RUST_LOG").ok().as_deref(),
                "hidravpn_issuer=info",
            ),
        ))
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
                Account::Add {
                    name,
                    quota,
                    prepaid,
                } => {
                    let token = Accounts::update(&path, |a| a.add(&name, quota, prepaid))??;
                    eprintln!(
                        "account {} added, {}. Its token, shown this once (only its hash is kept):",
                        name.trim(),
                        match prepaid {
                            Some(n) => format!("{n} passes in all"),
                            None => format!("{quota} passes a day"),
                        }
                    );
                    println!("{token}");
                }
                Account::List => {
                    let a = Accounts::load(&path)?;
                    for e in &a.accounts {
                        let used = if e.day == today() { e.used } else { 0 };
                        match e.balance {
                            Some(b) => println!(
                                "{:<32} {:>6} left (prepaid)       {}",
                                e.name,
                                b,
                                if e.enabled { "on" } else { "OFF" }
                            ),
                            None => println!(
                                "{:<32} {:>6}/day  {:>6} used today  {}",
                                e.name,
                                e.quota_per_day,
                                used,
                                if e.enabled { "on" } else { "OFF" }
                            ),
                        }
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
            pay_wallet,
            pay_packs,
            pay_mint,
            pay_decimals,
            pay_rpc,
            pay_price_urls,
            pay_price_every,
            pay_price_max_age,
            pay_price_max_change,
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
            let payments = match (pay_wallet, pay_packs.is_empty()) {
                (None, true) => None,
                (None, false) => {
                    return Err(anyhow!(
                        "--pay-pack needs --pay-wallet, the wallet payments go to"
                    ))
                }
                (Some(_), true) => {
                    return Err(anyhow!(
                        "--pay-wallet needs at least one --pay-pack PASSES=PRICE"
                    ))
                }
                (Some(wallet), false) => {
                    let urls = if pay_price_urls.is_empty() {
                        vec![Rate::default_url(&pay_mint)]
                    } else {
                        pay_price_urls
                    };
                    let feed = RateFeed {
                        urls,
                        every: Duration::from_secs(pay_price_every),
                        max_age: i64::try_from(pay_price_max_age).unwrap_or(i64::MAX),
                        max_change: f64::from(pay_price_max_change) / 100.0,
                    };
                    let p = Payments::new(
                        &wallet,
                        &pay_mint,
                        pay_decimals,
                        &pay_rpc,
                        &pay_packs,
                        Some(feed),
                        cli.orders.clone(),
                    )?;
                    Orders::load(&cli.orders)?;
                    Some(p)
                }
            };
            let issuer = Arc::new(Issuer {
                keys: loaded,
                accounts_path: cli.accounts.clone(),
                lock: Mutex::new(()),
                payments,
            });
            // The going rate, kept fresh for as long as the issuer runs,
            // for packs priced in dollars.
            if let Some(every) = issuer
                .payments
                .as_ref()
                .and_then(|p| p.rate.as_ref())
                .map(|r| r.feed.every)
            {
                let me = issuer.clone();
                tokio::spawn(async move {
                    loop {
                        if let Some(r) = me.payments.as_ref().and_then(|p| p.rate.as_ref()) {
                            r.refresh().await;
                        }
                        tokio::time::sleep(every).await;
                    }
                });
            }
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
        let t = a.add("alice", 5, None).unwrap();
        assert!(a.add("alice", 5, None).is_err(), "names are unique");
        assert!(a.add("has space", 5, None).is_err());
        assert_eq!(a.charge(&t, 3, 100), Ok((2, false)));
        assert_eq!(a.charge(&t, 3, 100), Err(Refused::Quota { left: 2 }));
        assert_eq!(a.charge(&t, 2, 100), Ok((0, false)));
        assert_eq!(a.charge(&t, 1, 100), Err(Refused::Quota { left: 0 }));
        assert_eq!(
            a.charge(&t, 1, 101),
            Ok((4, false)),
            "a new day, a new quota"
        );
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
                    Accounts::update(&path, |a| a.add(&format!("acct-{i}"), 1, None))
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
    fn a_token_nobody_issued_never_makes_the_issuer_write() {
        use std::os::unix::fs::MetadataExt;
        let dir =
            std::env::temp_dir().join(format!("hidravpn-issuer-nowrite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.json");
        let _ = std::fs::remove_file(&path);
        let token = Accounts::update(&path, |a| a.add("someone", 3, None))
            .unwrap()
            .unwrap();
        let day = today();
        Accounts::update(&path, |a| a.charge(&token, 1, day))
            .unwrap()
            .unwrap();
        let ino = std::fs::metadata(&path).unwrap().ino();
        let r = Accounts::update(&path, |a| a.charge("not-a-token", 1, day)).unwrap();
        assert_eq!(r, Err(Refused::UnknownToken));
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            ino,
            "the file was not rewritten"
        );
        Accounts::update(&path, |a| a.charge(&token, 1, day))
            .unwrap()
            .unwrap();
        assert_ne!(
            std::fs::metadata(&path).unwrap().ino(),
            ino,
            "a real charge is written"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_prepaid_account_spends_its_balance_and_a_purchase_tops_it_up() {
        let mut a = Accounts::default();
        let t = a.add("carol", 100, Some(3)).unwrap();
        assert_eq!(a.charge(&t, 2, 100), Ok((1, true)));
        assert_eq!(a.charge(&t, 2, 100), Err(Refused::Balance { left: 1 }));
        assert_eq!(
            a.charge(&t, 1, 5000),
            Ok((0, true)),
            "no day resets a balance"
        );
        assert_eq!(a.charge(&t, 1, 5000), Err(Refused::Balance { left: 0 }));
        a.refund(&t, 1, 5000);
        assert_eq!(a.balance_of(&token_hash(&t)), Some(1));
        assert_eq!(a.credit(&token_hash(&t), 10).unwrap(), 11);
        // A token nobody made an account for: a purchase makes one, prepaid,
        // under a name that says nothing.
        let fresh = token_hash("fresh-token");
        assert_eq!(a.balance_of(&fresh), None);
        assert_eq!(a.credit(&fresh, 10).unwrap(), 10);
        let made = a.accounts.iter().find(|x| x.token_sha256 == fresh).unwrap();
        assert!(
            made.name.starts_with("paid-") && made.balance == Some(10) && made.quota_per_day == 0
        );
        assert_eq!(a.charge("fresh-token", 4, 1), Ok((6, true)));
        // An account with a daily quota that buys becomes prepaid.
        let d = a.add("dave", 5, None).unwrap();
        assert_eq!(a.charge(&d, 1, 100), Ok((4, false)));
        assert_eq!(a.credit(&token_hash(&d), 20).unwrap(), 20);
        assert_eq!(a.charge(&d, 1, 100), Ok((19, true)));
    }

    #[test]
    fn orders_take_an_amount_of_their_own_and_lapse() {
        let mut o = Orders::default();
        let pack = Pack {
            passes: 10,
            price_raw: 50_000_000,
            usd_cents: None,
        };
        let h1 = token_hash("one");
        let h2 = token_hash("two");
        let a = o.open(&h1, &pack, 1000, 6).unwrap();
        let b = o.open(&h2, &pack, 1000, 6).unwrap();
        assert!(a.amount_raw > 50_000_000 && a.amount_raw <= 50_099_999);
        assert_ne!(
            a.amount_raw, b.amount_raw,
            "two open orders never share an amount"
        );
        // One token may hold a few orders at once, not more.
        for _ in 1..MAX_OPEN_PER_ACCOUNT {
            o.open(&h1, &pack, 1000, 6).unwrap();
        }
        assert_eq!(o.open(&h1, &pack, 1000, 6), Err(Full::Account));
        // Before a claim: the token's open orders, counted as one try each;
        // nothing for a token with none.
        match o.before_claim(&h2, "sig-hash", 1001).unwrap() {
            Claimable::Open(v) => assert_eq!((v.len(), v[0].tries), (1, 1)),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            o.before_claim(&token_hash("nobody"), "sig-hash", 1001),
            Err(NotClaimable::NoOrder)
        );
        // Paid: the transaction is used up, and the same claim again says so.
        o.mark_paid(&h2, b.amount_raw, "sig-hash", 1002).unwrap();
        assert_eq!(
            o.before_claim(&h2, "sig-hash", 1003).unwrap(),
            Claimable::AlreadyPaid {
                passes: 10,
                amount_raw: b.amount_raw
            }
        );
        assert_eq!(
            o.before_claim(&h1, "sig-hash", 1003),
            Err(NotClaimable::Used)
        );
        assert_eq!(
            o.mark_paid(&h1, a.amount_raw, "sig-hash", 1003),
            Err(NotClaimable::Used)
        );
        // Two orders of one token made in the same second are told apart
        // by their amounts.
        let twin = o.open(&h2, &pack, b.created, 6).unwrap();
        o.mark_paid(&h2, twin.amount_raw, "twin-sig", 1003).unwrap();
        assert_eq!(
            o.before_claim(&h2, "twin-sig", 1003).unwrap(),
            Claimable::AlreadyPaid {
                passes: 10,
                amount_raw: twin.amount_raw
            }
        );
        // A paid order's amount may be reused by a new order.
        let c = o.open(&h2, &pack, 1004, 6).unwrap();
        assert!(c.open_at(1004));
        // Too many tries on one token's orders.
        for _ in 0..MAX_CLAIM_TRIES {
            let _ = o.before_claim(&h1, "other", 1005);
        }
        assert_eq!(
            o.before_claim(&h1, "other", 1005),
            Err(NotClaimable::TooManyTries)
        );
        // Lapsed: gone, no claim; the used list outlives it.
        let later = 1000 + ORDER_LIFETIME + 1;
        assert_eq!(
            o.before_claim(&h1, "third", later),
            Err(NotClaimable::NoOrder)
        );
        assert!(
            o.orders
                .iter()
                .all(|x| x.paid_sha256.is_some() || x.created == 1004),
            "unpaid lapsed orders are pruned; the one made later stays"
        );
        assert_eq!(
            o.before_claim(&h1, "sig-hash", later),
            Err(NotClaimable::Used)
        );
        let much_later = 1000 + 3 * ORDER_LIFETIME;
        o.prune(much_later);
        assert!(o.orders.is_empty() && o.used.is_empty());
        // Undoing a mark puts the order back and frees the transaction.
        let d = o.open(&h1, &pack, much_later, 6).unwrap();
        o.mark_paid(&h1, d.amount_raw, "s", much_later).unwrap();
        o.unmark(&h1, d.amount_raw, "s");
        assert!(o.orders[0].open_at(much_later) && o.used.is_empty());
        // The file keeps hashes only.
        let json = serde_json::to_string(&o).unwrap();
        assert!(!json.contains("one") || json.contains(&h1));
        assert_eq!(rfc3339_full(951_868_800 + 3661), "2000-03-01T01:01:01Z");
    }

    #[tokio::test]
    async fn a_pack_is_sold_for_the_exact_amount_seen_on_chain() {
        use tokio::io::AsyncWriteExt;
        let dir = std::env::temp_dir().join(format!("hidravpn-issuer-pay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        const WALLET: &str = "So11111111111111111111111111111111111111112";
        const PAYER: &str = "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc";
        // A stand-in for the chain's RPC: it answers `getTransaction` for
        // the signatures it is told about, with the amount given.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        // (signature, amount, block time, succeeded)
        type Seen = Vec<(String, u64, i64, bool)>;
        let known: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Vec::new()));
        let chain = known.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let req = read_request(&mut s).await.unwrap();
                let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                let sig = v["params"][0].as_str().unwrap().to_string();
                let result = chain
                    .lock()
                    .await
                    .iter()
                    .find(|(k, _, _, _)| *k == sig)
                    .map(|(_, amount, time, ok)| {
                        serde_json::json!({
                            "blockTime": time, "slot": 1, "transaction": {},
                            "meta": {
                                "err": if *ok { serde_json::Value::Null } else { serde_json::json!({"x": 1}) },
                                "preTokenBalances": [
                                    {"accountIndex": 1, "owner": PAYER, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": "900000000", "decimals": 6}},
                                    {"accountIndex": 2, "owner": WALLET, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": "1000", "decimals": 6}}
                                ],
                                "postTokenBalances": [
                                    {"accountIndex": 1, "owner": PAYER, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": (900_000_000 - amount).to_string(), "decimals": 6}},
                                    {"accountIndex": 2, "owner": WALLET, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": (1000 + amount).to_string(), "decimals": 6}}
                                ]
                            }
                        })
                    })
                    .unwrap_or(serde_json::Value::Null);
                let body =
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
                let _ = s.write_all(&http_response(200, &body)).await;
            }
        });
        let secret = IssuerSecret::generate().unwrap();
        let record = PassKeyRecord {
            id: secret.public().id_hex(),
            key: secret.public().to_spki_base64(),
            not_after: "2100-01-01T00:00:00Z".into(),
        };
        let issuer = Arc::new(Issuer {
            keys: vec![(secret, record.clone())],
            accounts_path: dir.join("accounts.json"),
            lock: Mutex::new(()),
            payments: Some(
                Payments::new(
                    WALLET,
                    payment::HNET_MINT,
                    6,
                    &[format!("http://127.0.0.1:{port}/")],
                    &["10=50".into(), "30=140".into()],
                    None,
                    dir.join("orders.json"),
                )
                .unwrap(),
            ),
        });
        // The packs are told.
        let (st, packs) = issuer.packs();
        let packs: PacksResponse = serde_json::from_str(&packs).unwrap();
        assert_eq!(
            (st, packs.packs.len(), packs.wallet.as_str()),
            (200, 2, WALLET)
        );
        // A quote: the price plus a tag, to the wallet, for 24 hours.
        let token = "a-token-the-client-made";
        let quote = |n: u32| {
            serde_json::to_vec(&QuoteRequest {
                token_sha256: token_hash(token),
                passes: n,
            })
            .unwrap()
        };
        assert_eq!(issuer.quote(&quote(7)).await.0, 400, "no such pack");
        let (st, q) = issuer.quote(&quote(10)).await;
        assert_eq!(st, 200, "{q}");
        let q: QuoteResponse = serde_json::from_str(&q).unwrap();
        assert!(q.amount_raw > 50_000_000 && q.amount_raw < 50_100_000 && q.wallet == WALLET);
        assert_eq!(q.amount, payment::amount_to_string(q.amount_raw, 6));
        let claim = |sig: &str| {
            serde_json::to_vec(&ClaimRequest {
                token: token.into(),
                signature: sig.into(),
            })
            .unwrap()
        };
        let sig = |n: u8| payment::base58_encode(&[n; 64]);
        // Not a signature; not paid yet; paid the wrong amount; failed; too early.
        assert_eq!(issuer.claim(&claim("nope")).await.0, 400);
        assert_eq!(issuer.claim(&claim(&sig(1))).await.0, 404, "not on chain");
        let now = hidravpn_core::timefmt::now_unix();
        known
            .lock()
            .await
            .push((sig(2), q.amount_raw - 1, now, true));
        known.lock().await.push((sig(3), q.amount_raw, now, false));
        known
            .lock()
            .await
            .push((sig(4), q.amount_raw, now - ORDER_LIFETIME, true));
        known.lock().await.push((sig(5), q.amount_raw, now, true));
        let (st, why) = issuer.claim(&claim(&sig(2))).await;
        assert!(st == 402 && why.contains("another amount"), "{st} {why}");
        let (st, why) = issuer.claim(&claim(&sig(3))).await;
        assert!(st == 402 && why.contains("failed"), "{st} {why}");
        let (st, why) = issuer.claim(&claim(&sig(4))).await;
        assert!(
            st == 402 && why.contains("older than this order"),
            "{st} {why}"
        );
        // Paid: the pack is credited to the token's account, made on the spot.
        let (st, c) = issuer.claim(&claim(&sig(5))).await;
        assert_eq!(st, 200, "{c}");
        let c: ClaimResponse = serde_json::from_str(&c).unwrap();
        assert_eq!((c.passes, c.balance, c.already_claimed), (10, 10, false));
        // The same claim again: nothing twice.
        let (st, c) = issuer.claim(&claim(&sig(5))).await;
        let c: ClaimResponse = serde_json::from_str(&c).unwrap();
        assert_eq!((st, c.balance, c.already_claimed), (200, 10, true));
        // The token now gets passes, prepaid.
        let node = hidravpn_core::ClientKey::generate()
            .unwrap()
            .public_base64();
        let key = record.issuer_key().unwrap();
        let (b, _) = hidravpn_core::pass::prepare(&key, &node).unwrap();
        let body = serde_json::to_vec(&IssueRequest {
            token: token.into(),
            key_id: record.id.clone(),
            blinded: vec![b.clone(), b.clone()],
        })
        .unwrap();
        let (st, answer) = issuer.issue(&body).await;
        assert_eq!(st, 200, "{answer}");
        let r: IssueResponse = serde_json::from_str(&answer).unwrap();
        assert_eq!((r.remaining_today, r.prepaid), (8, true));
        // A second order, paid; the same transaction cannot pay a third.
        let (_, q2) = issuer.quote(&quote(30)).await;
        let q2: QuoteResponse = serde_json::from_str(&q2).unwrap();
        assert_ne!(q2.amount_raw, q.amount_raw);
        known
            .lock()
            .await
            .push((sig(6), q2.amount_raw, now + 1, true));
        let (st, c) = issuer.claim(&claim(&sig(6))).await;
        let c: ClaimResponse = serde_json::from_str(&c).unwrap();
        assert_eq!((st, c.passes, c.balance), (200, 30, 38));
        let (_, q3) = issuer.quote(&quote(30)).await;
        let q3: QuoteResponse = serde_json::from_str(&q3).unwrap();
        known
            .lock()
            .await
            .push((sig(7), q3.amount_raw, now + 1, true));
        // Another token claiming with that transaction: no order of its
        // own; and with a stolen order? It has no token.
        let other = serde_json::to_vec(&ClaimRequest {
            token: "someone-else".into(),
            signature: sig(7),
        })
        .unwrap();
        assert_eq!(issuer.claim(&other).await.0, 404);
        assert_eq!(
            issuer.claim(&claim(&sig(6))).await.0,
            200,
            "the paid order still answers"
        );
        let (st, _) = issuer.claim(&claim(&sig(7))).await;
        assert_eq!(st, 200);
        assert_eq!(issuer.claim(&claim(&sig(7))).await.0, 200);
        // The files hold hashes, never the token, the signatures or the wallet.
        let orders = std::fs::read_to_string(dir.join("orders.json")).unwrap();
        let accounts = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        for secret in [token, &sig(5), &sig(6), &sig(7)] {
            assert!(!orders.contains(secret) && !accounts.contains(secret));
        }
        assert!(!orders.contains(WALLET));
        // Payments off: the paths are not there.
        let plain = Arc::new(Issuer {
            keys: Vec::new(),
            accounts_path: dir.join("accounts.json"),
            lock: Mutex::new(()),
            payments: None,
        });
        assert_eq!(plain.quote(&quote(10)).await.0, 404);
        assert_eq!(plain.claim(&claim(&sig(5))).await.0, 404);
        assert_eq!(plain.packs().0, 404);
        // What run refuses.
        assert!(Payments::new(
            WALLET,
            payment::HNET_MINT,
            6,
            &["https://x/".into()],
            &["10=50.5".into()],
            None,
            dir.join("o")
        )
        .is_err());
        assert!(Payments::new(
            WALLET,
            payment::HNET_MINT,
            6,
            &["https://x/".into()],
            &["10=50".into(), "10=60".into()],
            None,
            dir.join("o")
        )
        .is_err());
        assert!(Payments::new(
            "not-an-address",
            payment::HNET_MINT,
            6,
            &["https://x/".into()],
            &["10=50".into()],
            None,
            dir.join("o")
        )
        .is_err());
        assert!(Payments::new(
            payment::HNET_MINT,
            payment::HNET_MINT,
            6,
            &["https://x/".into()],
            &["10=50".into()],
            None,
            dir.join("o")
        )
        .is_err());
        assert!(
            Payments::new(
                WALLET,
                payment::HNET_MINT,
                6,
                &["http://example.org/".into()],
                &["10=50".into()],
                None,
                dir.join("o")
            )
            .is_err(),
            "plain HTTP to the open internet"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_large_move_of_the_rate_waits_for_the_feed_to_insist() {
        let mut s = RateState::default();
        assert!(
            Rate::offer(&mut s, 0.0001, 1, 0.3),
            "the first rate is taken"
        );
        assert!(Rate::offer(&mut s, 0.00012, 2, 0.3), "20 % up: taken");
        assert!(!Rate::offer(&mut s, 0.0003, 3, 0.3), "150 % up: held");
        assert_eq!(s.current.map(|c| c.0), Some(0.00012));
        assert!(
            !Rate::offer(&mut s, 0.00031, 4, 0.3),
            "the feed insists: held still"
        );
        assert!(
            Rate::offer(&mut s, 0.00029, 5, 0.3),
            "three in a row: taken"
        );
        assert_eq!(s.current.map(|c| c.0), Some(0.00029));
        assert!(!Rate::offer(&mut s, 0.00001, 6, 0.3), "a crash: held");
        assert!(
            Rate::offer(&mut s, 0.00028, 7, 0.3),
            "back to normal: taken, the held one forgotten"
        );
        assert_eq!(s.held, None);
        assert!(!Rate::offer(&mut s, 0.00001, 8, 0.3));
        assert!(
            !Rate::offer(&mut s, 0.001, 9, 0.3),
            "two different wild rates do not add up"
        );
        assert_eq!(s.held, Some((0.001, 1)));
        let r = Rate::new(
            RateFeed {
                urls: vec![Rate::default_url(payment::HNET_MINT)],
                every: Duration::from_secs(300),
                max_age: 3600,
                max_change: 0.3,
            },
            payment::HNET_MINT,
        )
        .unwrap();
        assert_eq!(r.current(10), None, "nothing fetched yet");
        r.state.lock().unwrap().current = Some((0.0001, 1000));
        assert_eq!(r.current(1000 + 3600), Some(0.0001));
        assert_eq!(r.current(1000 + 3601), None, "stale");
    }

    #[test]
    fn a_payment_is_credited_only_on_a_strict_majority() {
        use payment::{Payment, Rejected};
        let p = |raw, t| Payment {
            paid_raw: raw,
            block_time: t,
        };
        let real = Payment {
            paid_raw: 50_000_000,
            block_time: 1700,
        };
        let paid = |x: Payment| Verdict::Paid(x);
        let rej = |r: Rejected| Verdict::Rejected(r);
        let down = || Verdict::Unreachable;

        // One RPC is its own majority: a one-RPC issuer is unchanged.
        assert_eq!(tally(&[paid(real)], 1), Quorum::Paid(real));
        assert_eq!(
            tally(&[rej(Rejected::NotFound)], 1),
            Quorum::Refused(Rejected::NotFound)
        );
        assert_eq!(tally(&[down()], 1), Quorum::Undecided);

        // Three RPCs, two agree on the same payment: confirmed, even past
        // one that is down or one that lies about the amount.
        assert_eq!(
            tally(&[paid(real), paid(real), down()], 3),
            Quorum::Paid(real)
        );
        assert_eq!(
            tally(&[paid(real), paid(real), paid(p(999, 1700))], 3),
            Quorum::Paid(real),
            "a lying minority cannot forge a payment"
        );

        // No two agree on the same payment: no quorum, nothing credited.
        assert_eq!(
            tally(&[paid(real), paid(p(999, 1700)), down()], 3),
            Quorum::Undecided
        );
        // Payments that differ only in block time are not the same payment.
        assert_eq!(
            tally(&[paid(real), paid(p(50_000_000, 1701)), down()], 3),
            Quorum::Undecided
        );
        // A split between a payment and a rejection is no quorum either.
        assert_eq!(
            tally(&[paid(real), rej(Rejected::NotFound), down()], 3),
            Quorum::Undecided
        );

        // A rejection a majority agree on carries through (the right
        // status reaches the client), but a payment always outweighs a
        // rejection at the same count.
        assert_eq!(
            tally(
                &[rej(Rejected::NotFound), rej(Rejected::NotFound), down()],
                3
            ),
            Quorum::Refused(Rejected::NotFound)
        );

        // Two RPCs: both must agree, so one down withholds the quorum.
        assert_eq!(tally(&[paid(real), paid(real)], 2), Quorum::Paid(real));
        assert_eq!(tally(&[paid(real), down()], 2), Quorum::Undecided);
    }

    /// Stands up a fake Solana RPC that answers `getTransaction` the same
    /// way for every signature: `Some((amount, time, ok))` for a transaction
    /// paying that much HNET to the wallet, or `None` for "not on chain".
    /// Returns the URL to give `--pay-rpc`.
    async fn fake_rpc(answer: Option<(u64, i64, bool)>) -> String {
        use tokio::io::AsyncWriteExt;
        const WALLET: &str = "So11111111111111111111111111111111111111112";
        const PAYER: &str = "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc";
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let _ = read_request(&mut s).await;
                let result = match answer {
                    Some((amount, time, ok)) => serde_json::json!({
                        "blockTime": time, "slot": 1, "transaction": {},
                        "meta": {
                            "err": if ok { serde_json::Value::Null } else { serde_json::json!({"x": 1}) },
                            "preTokenBalances": [
                                {"accountIndex": 2, "owner": WALLET, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": "1000", "decimals": 6}}
                            ],
                            "postTokenBalances": [
                                {"accountIndex": 1, "owner": PAYER, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": "1", "decimals": 6}},
                                {"accountIndex": 2, "owner": WALLET, "mint": payment::HNET_MINT, "uiTokenAmount": {"amount": (1000 + amount).to_string(), "decimals": 6}}
                            ]
                        }
                    }),
                    None => serde_json::Value::Null,
                };
                let body =
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
                let _ = s.write_all(&http_response(200, &body)).await;
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    #[tokio::test]
    async fn confirm_credits_only_what_a_majority_of_rpcs_agree_on() {
        const WALLET: &str = "So11111111111111111111111111111111111111112";
        let dir =
            std::env::temp_dir().join(format!("hidravpn-issuer-quorum-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paid = payment::Payment {
            paid_raw: 50_000_000,
            block_time: 1700,
        };
        let payments = |rpcs: &[String]| {
            Payments::new(
                WALLET,
                payment::HNET_MINT,
                6,
                rpcs,
                &["10=50".into()],
                None,
                dir.join("orders.json"),
            )
            .unwrap()
        };

        // Two honest RPCs and one that forges a different amount: the two
        // outvote the liar, so the real payment is confirmed.
        let honest_a = fake_rpc(Some((50_000_000, 1700, true))).await;
        let honest_b = fake_rpc(Some((50_000_000, 1700, true))).await;
        let liar = fake_rpc(Some((999, 1700, true))).await;
        let p = payments(&[honest_a.clone(), honest_b.clone(), liar.clone()]);
        assert_eq!(p.confirm("any-signature").await, Quorum::Paid(paid));

        // Honest two disagree with each other, the third is not on chain:
        // no majority reads the same payment, so nothing is credited.
        let other = fake_rpc(Some((60_000_000, 1700, true))).await;
        let missing = fake_rpc(None).await;
        let p = payments(&[honest_a, other, missing]);
        assert_eq!(p.confirm("any-signature").await, Quorum::Undecided);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_pack_in_dollars_is_sold_at_the_going_rate_or_not_at_all() {
        use tokio::io::AsyncWriteExt;
        let dir = std::env::temp_dir().join(format!("hidravpn-issuer-usd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        const WALLET: &str = "So11111111111111111111111111111111111111112";
        // A stand-in for the price feed, answering the rate it is set to.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let price = Arc::new(std::sync::Mutex::new(String::from("0.00012686")));
        let feed_price = price.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let _ = read_request(&mut s).await;
                let p = feed_price.lock().unwrap().clone();
                let body = if p == "down" {
                    "not json".to_string()
                } else {
                    serde_json::json!([{
                        "baseToken": {"address": payment::HNET_MINT},
                        "priceUsd": p, "liquidity": {"usd": 1000.0}
                    }])
                    .to_string()
                };
                let _ = s.write_all(&http_response(200, &body)).await;
            }
        });
        let payments = Payments::new(
            WALLET,
            payment::HNET_MINT,
            6,
            &["https://example.org/".into()],
            &["150=5.99usd".into(), "10=50".into()],
            Some(RateFeed {
                urls: vec![format!("http://127.0.0.1:{port}/")],
                every: Duration::from_secs(1),
                max_age: 2,
                max_change: 0.3,
            }),
            dir.join("orders.json"),
        )
        .unwrap();
        assert!(
            Payments::new(
                WALLET,
                payment::HNET_MINT,
                6,
                &["https://example.org/".into()],
                &["150=5.99usd".into()],
                None,
                dir.join("o")
            )
            .is_err(),
            "dollars need a feed"
        );
        let issuer = Arc::new(Issuer {
            keys: Vec::new(),
            accounts_path: dir.join("accounts.json"),
            lock: Mutex::new(()),
            payments: Some(payments),
        });
        let p = issuer.payments.as_ref().unwrap();
        // Before the first fetch: the fixed pack only, and no quote in dollars.
        let packs: PacksResponse = serde_json::from_str(&issuer.packs().1).unwrap();
        assert_eq!((packs.packs.len(), packs.rate.is_none()), (1, true));
        let quote = |n: u32| {
            serde_json::to_vec(&QuoteRequest {
                token_sha256: token_hash("t"),
                passes: n,
            })
            .unwrap()
        };
        let (st, why) = issuer.quote(&quote(150)).await;
        assert!(st == 503 && why.contains("not known"), "{st} {why}");
        assert_eq!(
            issuer.quote(&quote(10)).await.0,
            200,
            "the fixed pack sells meanwhile"
        );
        // Fetched: 5.99 dollars at 0.00012686 is 47 217 HNET.
        p.rate.as_ref().unwrap().refresh().await;
        let packs: PacksResponse = serde_json::from_str(&issuer.packs().1).unwrap();
        let usd = packs.packs.iter().find(|k| k.passes == 150).unwrap();
        assert_eq!(
            (usd.price_raw, usd.usd_cents, packs.rate.as_deref()),
            (47_217_000_000, Some(599), Some("0.00012686"))
        );
        let (st, q) = issuer.quote(&quote(150)).await;
        let q: QuoteResponse = serde_json::from_str(&q).unwrap();
        assert_eq!(st, 200);
        assert!(
            q.amount_raw > 47_217_000_000 && q.amount_raw < 47_217_100_000,
            "{}",
            q.amount
        );
        assert_eq!(
            (q.usd.as_deref(), q.rate.as_deref()),
            (Some("5.99"), Some("0.00012686"))
        );
        // The token doubles in a minute: held, the amount stands; insisted
        // on three times, taken: fewer HNET for the same dollars.
        *price.lock().unwrap() = "0.00025372".into();
        p.rate.as_ref().unwrap().refresh().await;
        let (_, q2) = issuer.quote(&quote(150)).await;
        let q2: QuoteResponse = serde_json::from_str(&q2).unwrap();
        assert_eq!(q2.rate.as_deref(), Some("0.00012686"), "held");
        p.rate.as_ref().unwrap().refresh().await;
        p.rate.as_ref().unwrap().refresh().await;
        let (_, q3) = issuer.quote(&quote(150)).await;
        let q3: QuoteResponse = serde_json::from_str(&q3).unwrap();
        assert!(
            q3.amount_raw > 23_609_000_000 && q3.amount_raw < 23_609_100_000,
            "{}",
            q3.amount
        );
        // The feed goes down: the last rate serves until it is too old,
        // then the pack is not for sale.
        *price.lock().unwrap() = "down".into();
        p.rate.as_ref().unwrap().refresh().await;
        assert_eq!(issuer.quote(&quote(150)).await.0, 200, "still fresh");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            issuer.quote(&quote(150)).await.0,
            503,
            "stale: not for sale"
        );
        let other = serde_json::to_vec(&QuoteRequest {
            token_sha256: token_hash("t2"),
            passes: 10,
        })
        .unwrap();
        assert_eq!(issuer.quote(&other).await.0, 200, "the fixed pack still is");
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
        let token = a.add("bob", 2, None).unwrap();
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
            payments: None,
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
