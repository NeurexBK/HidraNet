//! Buying passes with HNET (phase 7): what a client and the issuer say to
//! each other, how an amount is written, and the check of a payment on
//! Solana. Nothing here talks to the network: the issuer fetches the
//! transaction and hands it to `check_payment`; the client only builds and
//! reads messages.
//!
//! How a purchase goes:
//!
//! 1. The client makes an account token (32 random bytes, as the issuer's
//!    `account add` does) and keeps it. It asks the issuer for a **quote**
//!    with the token's SHA-256 and the pack it wants (`POST /quote`).
//! 2. The issuer answers an **order**: the pack's price plus a few random
//!    micro-HNET that no other open order has, so the amount names the
//!    order; the receiving wallet; the mint; when the order lapses
//!    (`UNCLAIMED_LIFETIME`, or `ORDER_LIFETIME` once a claim reached it).
//! 3. The person sends exactly that amount, from any Solana wallet, to the
//!    receiving wallet. Nothing but the amount is needed: no memo, no
//!    special wallet.
//! 4. The client **claims** with the token and the transaction's signature
//!    (`POST /claim`). The issuer looks the transaction up (finalized),
//!    checks that it moved exactly the order's amount of the right token to
//!    the receiving wallet, after the order was made, that it was never
//!    used before, and then credits the pack to the account the token
//!    names. From then on `POST /issue` works with that token as with any
//!    account.
//!
//! What protects the order against someone who watches the chain: the
//! amount is public, the token is not. A claim needs the token whose hash
//! made the order; a transaction seen on chain is of no use to anyone else.
//! The token only ever travels over TLS, and the issuer keeps its hash.
//!
//! What stays off the record: no log on the issuer names a wallet, a
//! transaction, an amount or a token; the orders file keeps the token's hash
//! and the transaction's hash, never either itself. A node never hears of a
//! payment: a pass bought this way is blind-signed like any other.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// The HNET mint on Solana, as the token page publishes it. An issuer may be
/// run for another token with `--pay-mint`.
pub const HNET_MINT: &str = "Aov3BtQvrGXM5V9oiHu8PKJWeV8a2rFnr24fwWcNpump";
/// HNET's decimals: one HNET is 1 000 000 raw units.
pub const HNET_DECIMALS: u8 = 6;
/// The random part of an amount: this many of the last digits.
pub const TAG_DIGITS: u32 = 5;
/// How long an order can be paid and claimed before any claim reached it,
/// in seconds (2 hours): what the quote says it is open until. An order
/// lives only so long unless its token claims it, so orders opened for
/// nobody's payment cannot fill the issuer.
pub const UNCLAIMED_LIFETIME: i64 = 2 * 3600;
/// How long an order a claim has reached stays open, counted from when it
/// was made, in seconds (24 hours): a claim that came too soon, before the
/// chain finalized the payment, or that the issuer could not answer, can
/// be made again.
pub const ORDER_LIFETIME: i64 = 24 * 3600;
/// What the issuer answers a claim it turns away only for now (429), after
/// the claim has reached the token's orders: the client knows these, to say
/// the order is still open.
pub const CLAIM_PACED: &str = "this token made many claims just now; try again in a few seconds";
pub const CLAIMS_BUSY: &str = "too many claims at once; try again in a moment";
/// A transaction may carry a block time this much before the order was made
/// (clocks differ) and still pay it.
pub const CLOCK_SLACK: i64 = 300;

// ---- base58 (the Bitcoin alphabet Solana uses) --------------------------------

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decodes base58 text to bytes. Refuses anything that is not base58.
pub fn base58_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() > 128 {
        return Err(anyhow!("not base58: empty or too long"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let mut carry = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| anyhow!("not base58: the character {:?}", c as char))?
            as u32;
        for b in out.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Each leading '1' is a leading zero byte.
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    out.extend(std::iter::repeat_n(0u8, zeros));
    out.reverse();
    Ok(out)
}

/// Encodes bytes as base58 text.
pub fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &b in bytes {
        let mut carry = u32::from(b);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut s = String::with_capacity(zeros + digits.len());
    s.extend(std::iter::repeat_n('1', zeros));
    s.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    s
}

/// A Solana address: 32 bytes in base58.
pub fn check_address(s: &str) -> Result<String> {
    let s = s.trim();
    let bytes = base58_decode(s).map_err(|e| anyhow!("{s:?} is not a Solana address: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{s:?} is not a Solana address (not 32 bytes)"));
    }
    Ok(s.to_string())
}

/// A transaction signature: 64 bytes in base58.
pub fn check_signature(s: &str) -> Result<String> {
    let s = s.trim();
    let bytes =
        base58_decode(s).map_err(|e| anyhow!("that is not a transaction signature: {e}"))?;
    if bytes.len() != 64 {
        return Err(anyhow!(
            "that is not a transaction signature (not 64 bytes); copy the whole signature from the wallet or the explorer"
        ));
    }
    Ok(s.to_string())
}

// ---- amounts ------------------------------------------------------------------

/// `raw` units written as a decimal amount: 50_004_213 with 6 decimals is
/// "50.004213". Always every decimal, so what the person types matches.
pub fn amount_to_string(raw: u64, decimals: u8) -> String {
    let scale = 10u64.pow(u32::from(decimals));
    if decimals == 0 {
        return raw.to_string();
    }
    format!(
        "{}.{:0width$}",
        raw / scale,
        raw % scale,
        width = decimals as usize
    )
}

/// A decimal amount as raw units: "50", "50.5" or "50.004213" with 6
/// decimals. More decimals than the token has, or anything that is not a
/// number, is refused.
pub fn amount_from_string(s: &str, decimals: u8) -> Result<u64> {
    let s = s.trim();
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(anyhow!("{s:?} is not an amount"));
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("{s:?} is not an amount"));
    }
    if frac.len() > decimals as usize {
        return Err(anyhow!(
            "{s:?} has more than {decimals} decimals, which the token does not have"
        ));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| anyhow!("{s:?} is too large an amount"))?
    };
    let mut frac_raw: u64 = if frac.is_empty() { 0 } else { frac.parse()? };
    frac_raw *= 10u64.pow(u32::from(decimals) - frac.len() as u32);
    whole
        .checked_mul(10u64.pow(u32::from(decimals)))
        .and_then(|w| w.checked_add(frac_raw))
        .ok_or_else(|| anyhow!("{s:?} is too large an amount"))
}

/// A pack as a client sees it: so many passes for so much of the token
/// (raw units), and, when the pack is priced in dollars, that price too:
/// `price_raw` is then today's equivalent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pack {
    pub passes: u32,
    pub price_raw: u64,
    /// The price in US cents, for a pack priced in dollars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_cents: Option<u64>,
}

/// A pack as the operator sets it: a price in whole tokens, or in dollars
/// that the issuer turns into tokens at the going rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSpec {
    pub passes: u32,
    pub price: Price,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Price {
    /// So many raw units, a whole number of tokens.
    Tokens(u64),
    /// So many US cents.
    Usd(u64),
}

impl PackSpec {
    /// "PASSES=PRICE": the price in whole tokens ("10=50") or in dollars
    /// ("150=5.99usd", "150=$5.99"). The random part of an amount takes the
    /// last `TAG_DIGITS` decimals, so a price in tokens keeps to whole
    /// tokens and the two never meet; a price in dollars is turned into
    /// whole tokens the same way.
    pub fn parse(spec: &str, decimals: u8) -> Result<PackSpec> {
        let (passes, price) = spec.trim().split_once('=').ok_or_else(|| {
            anyhow!("a pack is PASSES=PRICE, such as 10=50 or 150=5.99usd; got {spec:?}")
        })?;
        let passes: u32 = passes.trim().parse().map_err(|_| {
            anyhow!("a pack is PASSES=PRICE, such as 10=50 or 150=5.99usd; got {spec:?}")
        })?;
        if passes == 0 || passes > 10_000 {
            return Err(anyhow!("a pack holds 1 to 10000 passes; got {spec:?}"));
        }
        let price = price.trim();
        let usd = price
            .strip_prefix('$')
            .or_else(|| price.strip_suffix("usd"))
            .or_else(|| price.strip_suffix("USD"))
            .or_else(|| price.strip_suffix(" USD"))
            .or_else(|| price.strip_suffix(" usd"));
        let price = match usd {
            Some(d) => {
                let cents = amount_from_string(d, 2)
                    .map_err(|_| anyhow!("a price in dollars is like 5.99usd; got {spec:?}"))?;
                if cents == 0 {
                    return Err(anyhow!("a pack's price is more than nothing; got {spec:?}"));
                }
                Price::Usd(cents)
            }
            None => {
                let price_raw = amount_from_string(price, decimals)?;
                let scale = 10u64.pow(u32::from(decimals));
                if price_raw == 0 || price_raw % scale != 0 {
                    return Err(anyhow!(
                        "a pack's price is a whole number of tokens, 1 or more, or dollars like 5.99usd; got {spec:?}"
                    ));
                }
                Price::Tokens(price_raw)
            }
        };
        Ok(PackSpec { passes, price })
    }

    /// The pack at the going rate (`usd_per_token`, dollars for one whole
    /// token): None when the price is in dollars and no rate is known.
    pub fn at(&self, usd_per_token: Option<f64>, decimals: u8) -> Option<Pack> {
        match self.price {
            Price::Tokens(price_raw) => Some(Pack {
                passes: self.passes,
                price_raw,
                usd_cents: None,
            }),
            Price::Usd(cents) => Some(Pack {
                passes: self.passes,
                price_raw: tokens_for_usd(cents, usd_per_token?, decimals)?,
                usd_cents: Some(cents),
            }),
        }
    }
}

/// How many raw units `cents` of a dollar buy at `usd_per_token`, rounded
/// to a whole token (never under one), or None for a rate that makes no
/// sense (zero, negative, not a number, or so small the amount overflows).
pub fn tokens_for_usd(cents: u64, usd_per_token: f64, decimals: u8) -> Option<u64> {
    if !usd_per_token.is_finite() || usd_per_token <= 0.0 {
        return None;
    }
    let tokens = (cents as f64 / 100.0 / usd_per_token).round().max(1.0);
    if !tokens.is_finite() || tokens > 1e15 {
        return None;
    }
    (tokens as u64).checked_mul(10u64.pow(u32::from(decimals)))
}

/// Dollars as "5.99", from cents.
pub fn usd_to_string(cents: u64) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// The most the random part of an amount can be: 10^TAG_DIGITS - 1 raw
/// units, or less for a token with fewer decimals.
pub fn tag_space(decimals: u8) -> u64 {
    10u64.pow(TAG_DIGITS.min(u32::from(decimals))) - 1
}

// ---- the wire -------------------------------------------------------------------

/// `POST /quote`: which pack, for the account whose token hashes to this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    pub token_sha256: String,
    pub passes: u32,
}

/// The order the issuer answers with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    pub passes: u32,
    /// Exactly what to send, as a decimal: "50.004213".
    pub amount: String,
    pub amount_raw: u64,
    pub decimals: u8,
    pub mint: String,
    pub wallet: String,
    /// RFC 3339; the order cannot be claimed after this.
    pub expires: String,
    /// For a pack priced in dollars: the price ("5.99") and the rate the
    /// amount was made at (dollars for one token), fixed for this order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
}

/// `POST /claim`: the token the order was made for, and the transaction
/// that paid it.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub token: String,
    pub signature: String,
}

impl std::fmt::Debug for ClaimRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the token nor the transaction.
        f.debug_struct("ClaimRequest").finish_non_exhaustive()
    }
}

/// What a claim credited: the pack, and the account's balance now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub passes: u32,
    pub balance: u32,
    /// The amount of the order the transaction paid: with several orders
    /// open, which one.
    #[serde(default)]
    pub amount_raw: u64,
    /// True when this same transaction had already paid an order of this
    /// token: the balance is as it was, nothing was credited twice.
    #[serde(default)]
    pub already_claimed: bool,
}

/// `GET /packs`: what can be bought, for a client to show.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacksResponse {
    pub packs: Vec<Pack>,
    pub decimals: u8,
    pub mint: String,
    pub wallet: String,
    #[serde(default)]
    pub token_name: String,
    /// The going rate, dollars for one token, when packs are priced in
    /// dollars and it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
}

/// A rate written for people: enough digits for a token worth very little.
pub fn rate_to_string(usd_per_token: f64) -> String {
    let s = format!("{usd_per_token:.10}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() {
        "0".into()
    } else {
        s.to_string()
    }
}

// ---- the going rate ---------------------------------------------------------------

/// Reads the token's price in dollars from what a DEX screener answers
/// about the mint (`https://api.dexscreener.com/tokens/v1/solana/<mint>`,
/// or the older `/latest/dex/tokens/<mint>`): among the pairs whose base
/// is the mint, the one with the most liquidity, its `priceUsd`. Pure: the
/// issuer fetches, this reads.
pub fn read_rate(answer: &str, mint: &str) -> Result<f64> {
    let v: serde_json::Value =
        serde_json::from_str(answer).context("the price feed's answer is not JSON")?;
    let pairs = match &v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Object(o) => o
            .get("pairs")
            .and_then(|p| p.as_array())
            .cloned()
            .ok_or_else(|| anyhow!("the price feed's answer lists no pairs"))?,
        _ => return Err(anyhow!("the price feed's answer lists no pairs")),
    };
    let mut best: Option<(f64, f64)> = None;
    for p in &pairs {
        let base = p
            .get("baseToken")
            .and_then(|b| b.get("address"))
            .and_then(|a| a.as_str())
            .unwrap_or("");
        if base != mint {
            continue;
        }
        let price: f64 = match p
            .get("priceUsd")
            .and_then(|x| x.as_str())
            .and_then(|x| x.parse().ok())
        {
            Some(x) => x,
            None => continue,
        };
        let liquidity = p
            .get("liquidity")
            .and_then(|l| l.get("usd"))
            .and_then(|u| u.as_f64())
            .unwrap_or(0.0);
        if price.is_finite() && price > 0.0 && best.is_none_or(|(l, _)| liquidity > l) {
            best = Some((liquidity, price));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| anyhow!("the price feed knows no pair of the token with a price"))
}

// ---- checking a transaction ------------------------------------------------------

/// The wallet and the token a payment must have reached.
#[derive(Debug, Clone)]
pub struct Receiver<'a> {
    pub wallet: &'a str,
    pub mint: &'a str,
    pub decimals: u8,
}

/// What a transaction paid the receiver: how much of the token, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payment {
    pub paid_raw: u64,
    pub block_time: i64,
}

impl Payment {
    /// Whether this payment pays an order of `amount_raw` made at
    /// `created` (unix): the exact amount, and not from before the order
    /// (less `CLOCK_SLACK`, as clocks differ).
    pub fn pays(&self, amount_raw: u64, created: i64) -> Result<(), Rejected> {
        if self.block_time < created - CLOCK_SLACK {
            return Err(Rejected::TooEarly);
        }
        if self.paid_raw != amount_raw {
            return Err(Rejected::WrongAmount {
                paid_raw: self.paid_raw,
            });
        }
        Ok(())
    }
}

/// Why a transaction does not pay an order. `Display` is what the client is
/// told; the variant is what the issuer logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// Not on chain, or not finalized yet.
    NotFound,
    /// Not shaped like `getTransaction`'s answer.
    Malformed,
    /// The transaction ran and failed.
    Failed,
    /// Older than the order.
    TooEarly,
    /// The token balances name other decimals than the issuer was told.
    Decimals,
    /// No HNET reached the receiving wallet.
    NoTransfer,
    /// Some did, but not the order's amount.
    WrongAmount { paid_raw: u64 },
}

impl Rejected {
    /// A short fixed word for the log.
    pub fn kind(&self) -> &'static str {
        match self {
            Rejected::NotFound => "not-found",
            Rejected::Malformed => "malformed",
            Rejected::Failed => "failed",
            Rejected::TooEarly => "too-early",
            Rejected::Decimals => "decimals",
            Rejected::NoTransfer => "no-transfer",
            Rejected::WrongAmount { .. } => "wrong-amount",
        }
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::NotFound => write!(
                f,
                "the transaction is not on chain as finalized yet; that takes under a minute, then try again"
            ),
            Rejected::Malformed => write!(f, "the chain's answer about the transaction is unreadable"),
            Rejected::Failed => write!(f, "the transaction failed on chain, so nothing was paid"),
            Rejected::TooEarly => write!(
                f,
                "the transaction is older than this order; a payment pays the order made before it"
            ),
            Rejected::Decimals => write!(f, "the token in the transaction is not the one this issuer takes"),
            Rejected::NoTransfer => write!(
                f,
                "the transaction moved none of the token to the receiving wallet; check the wallet address and the token"
            ),
            Rejected::WrongAmount { .. } => write!(
                f,
                "the transaction paid another amount than this order's; the amount must match exactly, every decimal"
            ),
        }
    }
}

/// Reads what the answer to `getTransaction` (the JSON-RPC `result`) paid
/// the receiver. Pure: the issuer fetches, this reads, `Payment::pays`
/// judges against an order.
///
/// What is read: `blockTime`, `meta.err`, and the token balances before and
/// after (`meta.preTokenBalances`, `meta.postTokenBalances`). The amount
/// that reached the wallet is the sum, over every token account the wallet
/// owns for the mint, of its balance after less its balance before. That
/// holds for a plain transfer, a checked one, an account made in the same
/// transaction, and for either token program.
pub fn inspect_payment(
    result: &serde_json::Value,
    want: &Receiver<'_>,
) -> Result<Payment, Rejected> {
    if result.is_null() {
        return Err(Rejected::NotFound);
    }
    let meta = result.get("meta").ok_or(Rejected::Malformed)?;
    if !meta.get("err").is_some_and(|e| e.is_null()) {
        // No `err` key at all is not an answer this reads; a non-null one
        // is a failed transaction.
        return Err(if meta.get("err").is_none() {
            Rejected::Malformed
        } else {
            Rejected::Failed
        });
    }
    let block_time = result
        .get("blockTime")
        .and_then(|t| t.as_i64())
        .ok_or(Rejected::Malformed)?;
    let balances = |key: &str| -> Result<Vec<(u64, u64, u8)>, Rejected> {
        // (account index, raw amount, decimals) of the wallet's accounts
        // for the mint. A missing list is an empty one (no token accounts
        // touched before, for instance).
        let Some(list) = meta.get(key) else {
            return Ok(Vec::new());
        };
        let list = list.as_array().ok_or(Rejected::Malformed)?;
        let mut v = Vec::new();
        for b in list {
            let owner = b.get("owner").and_then(|o| o.as_str()).unwrap_or("");
            let mint = b.get("mint").and_then(|m| m.as_str()).unwrap_or("");
            if owner != want.wallet || mint != want.mint {
                continue;
            }
            let index = b
                .get("accountIndex")
                .and_then(|i| i.as_u64())
                .ok_or(Rejected::Malformed)?;
            let ui = b.get("uiTokenAmount").ok_or(Rejected::Malformed)?;
            let amount: u64 = ui
                .get("amount")
                .and_then(|a| a.as_str())
                .and_then(|a| a.parse().ok())
                .ok_or(Rejected::Malformed)?;
            let decimals = ui
                .get("decimals")
                .and_then(|d| d.as_u64())
                .and_then(|d| u8::try_from(d).ok())
                .ok_or(Rejected::Malformed)?;
            v.push((index, amount, decimals));
        }
        Ok(v)
    };
    let before = balances("preTokenBalances")?;
    let after = balances("postTokenBalances")?;
    if before
        .iter()
        .chain(&after)
        .any(|&(_, _, d)| d != want.decimals)
    {
        return Err(Rejected::Decimals);
    }
    let mut received: i128 = 0;
    for &(index, post, _) in &after {
        let pre = before
            .iter()
            .find(|&&(i, _, _)| i == index)
            .map(|&(_, a, _)| a)
            .unwrap_or(0);
        received += i128::from(post) - i128::from(pre);
    }
    // An account the wallet had before and closed in the transaction shows
    // in `pre` only: what it held left the wallet.
    for &(index, pre, _) in &before {
        if !after.iter().any(|&(i, _, _)| i == index) {
            received -= i128::from(pre);
        }
    }
    if received <= 0 {
        return Err(Rejected::NoTransfer);
    }
    let paid_raw = u64::try_from(received).map_err(|_| Rejected::Malformed)?;
    Ok(Payment {
        paid_raw,
        block_time,
    })
}

/// `inspect_payment` and `Payment::pays` in one: whether the answer pays an
/// order of `amount_raw` made at `created`.
pub fn check_payment(
    result: &serde_json::Value,
    want: &Receiver<'_>,
    amount_raw: u64,
    created: i64,
) -> Result<(), Rejected> {
    inspect_payment(result, want)?.pays(amount_raw, created)
}

/// The JSON-RPC request that fetches a transaction the way `check_payment`
/// reads it: `json` encoding (the balances are in `meta` either way, and
/// the parsed form is larger), finalized only, any transaction version.
pub fn get_transaction_request(signature: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [signature, {
            "encoding": "json",
            "commitment": "finalized",
            "maxSupportedTransactionVersion": 0
        }]
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips_and_refuses_what_is_not() {
        // Known vectors (the Bitcoin test set).
        assert_eq!(base58_encode(b""), "");
        assert_eq!(base58_encode(&[0]), "1");
        assert_eq!(base58_encode(&[0, 0, 1]), "112");
        assert_eq!(base58_encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58_decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
        assert_eq!(base58_decode("112").unwrap(), vec![0, 0, 1]);
        for bad in ["", "0", "O", "I", "l", "abc def", "+"] {
            assert!(base58_decode(bad).is_err(), "{bad:?}");
        }
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i * 37 % 251) as u8;
        }
        assert_eq!(base58_decode(&base58_encode(&bytes)).unwrap(), bytes);
        // Real addresses are 32 bytes; a signature 64.
        check_address(HNET_MINT).unwrap();
        check_address("So11111111111111111111111111111111111111112").unwrap();
        assert!(check_address("StV1DL6CwTryKyV").is_err());
        assert!(check_signature(HNET_MINT).is_err());
        check_signature(&base58_encode(&bytes)).unwrap();
    }

    #[test]
    fn amounts_are_written_and_read_with_every_decimal() {
        assert_eq!(amount_to_string(50_004_213, 6), "50.004213");
        assert_eq!(amount_to_string(50_000_000, 6), "50.000000");
        assert_eq!(amount_to_string(7, 6), "0.000007");
        assert_eq!(amount_to_string(7, 0), "7");
        assert_eq!(amount_from_string("50.004213", 6).unwrap(), 50_004_213);
        assert_eq!(amount_from_string("50", 6).unwrap(), 50_000_000);
        assert_eq!(amount_from_string("50.5", 6).unwrap(), 50_500_000);
        assert_eq!(amount_from_string(".5", 6).unwrap(), 500_000);
        assert_eq!(amount_from_string("0", 6).unwrap(), 0);
        for bad in [
            "",
            ".",
            "1.2.3",
            "-5",
            "5e3",
            "50.0000001",
            "abc",
            "99999999999999999999",
        ] {
            assert!(amount_from_string(bad, 6).is_err(), "{bad:?}");
        }
        for raw in [0u64, 1, 999_999, 1_000_000, 123_456_789_012] {
            assert_eq!(
                amount_from_string(&amount_to_string(raw, 6), 6).unwrap(),
                raw
            );
        }
    }

    #[test]
    fn packs_are_whole_tokens_or_dollars_for_some_passes() {
        assert_eq!(
            PackSpec::parse("10=50", 6).unwrap(),
            PackSpec {
                passes: 10,
                price: Price::Tokens(50_000_000)
            }
        );
        assert_eq!(PackSpec::parse(" 100 = 400 ", 6).unwrap().passes, 100);
        for spec in ["150=5.99usd", "150=$5.99", "150=5.99 USD", "150=5.99USD"] {
            assert_eq!(
                PackSpec::parse(spec, 6).unwrap(),
                PackSpec {
                    passes: 150,
                    price: Price::Usd(599)
                },
                "{spec}"
            );
        }
        for bad in [
            "10",
            "10=",
            "=50",
            "0=50",
            "10=0",
            "10=50.5",
            "10=x",
            "20000=1",
            "10=5.999usd",
            "10=$0",
            "10=$x",
        ] {
            assert!(PackSpec::parse(bad, 6).is_err(), "{bad:?}");
        }
        assert_eq!(tag_space(6), 99_999);
        assert_eq!(tag_space(2), 99);
        // At the going rate: 5.99 dollars at 0.00012686 a token is 47 215
        // whole tokens; with no rate, no pack; a fixed price needs none.
        let usd = PackSpec::parse("150=5.99usd", 6).unwrap();
        assert_eq!(
            usd.at(Some(5.99 / 47_215.319), 6).unwrap(),
            Pack {
                passes: 150,
                price_raw: 47_215_000_000,
                usd_cents: Some(599)
            }
        );
        assert_eq!(usd.at(None, 6), None);
        assert_eq!(usd.at(Some(0.0), 6), None);
        assert_eq!(usd.at(Some(f64::NAN), 6), None);
        assert_eq!(
            usd.at(Some(1e-20), 6),
            None,
            "an amount past what a u64 holds"
        );
        assert_eq!(
            usd.at(Some(1000.0), 6).unwrap().price_raw,
            1_000_000,
            "never under one token"
        );
        let fixed = PackSpec::parse("10=50", 6).unwrap();
        assert_eq!(fixed.at(None, 6).unwrap().price_raw, 50_000_000);
        assert_eq!(usd_to_string(599), "5.99");
        assert_eq!(usd_to_string(5), "0.05");
        assert_eq!(rate_to_string(0.00012686), "0.00012686");
        assert_eq!(rate_to_string(1.5), "1.5");
    }

    #[test]
    fn the_rate_is_the_deepest_pair_of_the_token() {
        let pair = |base: &str, price: &str, liq: f64| {
            serde_json::json!({
                "baseToken": {"address": base, "symbol": "X"},
                "quoteToken": {"address": OTHER},
                "priceUsd": price,
                "liquidity": {"usd": liq}
            })
        };
        let a = serde_json::json!([
            pair(HNET_MINT, "0.0001", 100.0),
            pair(HNET_MINT, "0.0002", 5000.0),
            pair(OTHER, "9", 1e9)
        ]);
        assert_eq!(read_rate(&a.to_string(), HNET_MINT).unwrap(), 0.0002);
        let old = serde_json::json!({"schemaVersion": "1.0.0", "pairs": [pair(HNET_MINT, "0.0003", 1.0)]});
        assert_eq!(read_rate(&old.to_string(), HNET_MINT).unwrap(), 0.0003);
        for bad in [
            "[]",
            "{}",
            "{\"pairs\": []}",
            "nope",
            "[{\"priceUsd\": \"1\"}]",
        ] {
            assert!(read_rate(bad, HNET_MINT).is_err(), "{bad}");
        }
        let zero = serde_json::json!([
            pair(HNET_MINT, "0", 100.0),
            pair(HNET_MINT, "-1", 100.0),
            pair(HNET_MINT, "x", 100.0)
        ]);
        assert!(read_rate(&zero.to_string(), HNET_MINT).is_err());
    }

    fn tx(pre: &[(u64, &str, &str, &str)], post: &[(u64, &str, &str, &str)]) -> serde_json::Value {
        let bal = |list: &[(u64, &str, &str, &str)]| -> Vec<serde_json::Value> {
            list.iter()
                .map(|(i, owner, mint, amount)| {
                    serde_json::json!({
                        "accountIndex": i, "owner": owner, "mint": mint,
                        "uiTokenAmount": {"amount": amount, "decimals": 6}
                    })
                })
                .collect()
        };
        serde_json::json!({
            "blockTime": 1_800_000_000,
            "slot": 1,
            "meta": {"err": null, "preTokenBalances": bal(pre), "postTokenBalances": bal(post)},
            "transaction": {}
        })
    }

    const W: &str = "So11111111111111111111111111111111111111112";
    const OTHER: &str = "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc";

    #[test]
    fn a_payment_is_the_exact_amount_of_the_token_to_the_wallet_after_the_order() {
        let who = Receiver {
            wallet: W,
            mint: HNET_MINT,
            decimals: 6,
        };
        let want = |r: &serde_json::Value| check_payment(r, &who, 50_004_213, 1_800_000_000 - 60);
        // The payer's account goes down, the wallet's goes up by the amount.
        let good = tx(
            &[(1, OTHER, HNET_MINT, "100000000"), (2, W, HNET_MINT, "5")],
            &[
                (1, OTHER, HNET_MINT, "49995787"),
                (2, W, HNET_MINT, "50004218"),
            ],
        );
        assert_eq!(want(&good), Ok(()));
        // The wallet's token account made in this very transaction: no
        // balance before.
        let fresh = tx(
            &[(1, OTHER, HNET_MINT, "100000000")],
            &[
                (1, OTHER, HNET_MINT, "49995787"),
                (2, W, HNET_MINT, "50004213"),
            ],
        );
        assert_eq!(want(&fresh), Ok(()));
        // Not there, or not finalized.
        assert_eq!(want(&serde_json::Value::Null), Err(Rejected::NotFound));
        // Another amount, even one unit off, even more.
        let off = tx(&[(2, W, HNET_MINT, "0")], &[(2, W, HNET_MINT, "50004212")]);
        assert_eq!(
            want(&off),
            Err(Rejected::WrongAmount {
                paid_raw: 50_004_212
            })
        );
        assert_eq!(
            inspect_payment(&off, &who),
            Ok(Payment {
                paid_raw: 50_004_212,
                block_time: 1_800_000_000
            })
        );
        let more = tx(&[(2, W, HNET_MINT, "0")], &[(2, W, HNET_MINT, "60000000")]);
        assert!(matches!(want(&more), Err(Rejected::WrongAmount { .. })));
        // Another token to the wallet, or the token to another wallet.
        let wrong_mint = tx(&[(2, W, OTHER, "0")], &[(2, W, OTHER, "50004213")]);
        assert_eq!(want(&wrong_mint), Err(Rejected::NoTransfer));
        let wrong_wallet = tx(
            &[(2, OTHER, HNET_MINT, "0")],
            &[(2, OTHER, HNET_MINT, "50004213")],
        );
        assert_eq!(want(&wrong_wallet), Err(Rejected::NoTransfer));
        // The balances say another decimals: not this token as configured.
        let mut dec = good.clone();
        dec["meta"]["postTokenBalances"][1]["uiTokenAmount"]["decimals"] = 9.into();
        assert_eq!(want(&dec), Err(Rejected::Decimals));
        // Failed on chain.
        let mut failed = good.clone();
        failed["meta"]["err"] = serde_json::json!({"InstructionError": [0, "Custom"]});
        assert_eq!(want(&failed), Err(Rejected::Failed));
        // Older than the order, past the slack.
        let mut early = good.clone();
        early["blockTime"] = (1_800_000_000i64 - 60 - CLOCK_SLACK - 1).into();
        assert_eq!(want(&early), Err(Rejected::TooEarly));
        // Within the slack: fine.
        early["blockTime"] = (1_800_000_000i64 - 60 - CLOCK_SLACK + 1).into();
        assert_eq!(want(&early), Ok(()));
        // Shapes that are not an answer.
        for broken in [
            serde_json::json!({}),
            serde_json::json!({"meta": {}}),
            serde_json::json!({"meta": {"err": null}}),
            serde_json::json!({"blockTime": 1_800_000_000, "meta": {"err": null, "postTokenBalances": 5}}),
        ] {
            assert_eq!(want(&broken), Err(Rejected::Malformed), "{broken}");
        }
        // A balance entry of the wallet that is not a number.
        let mut nan = good.clone();
        nan["meta"]["postTokenBalances"][1]["uiTokenAmount"]["amount"] = "lots".into();
        assert_eq!(want(&nan), Err(Rejected::Malformed));
        // Money moving out of the wallet is not a payment in.
        let out = tx(&[(2, W, HNET_MINT, "50004213")], &[(2, W, HNET_MINT, "0")]);
        assert_eq!(want(&out), Err(Rejected::NoTransfer));
        // Two accounts of the wallet: one closed, one filled; the net counts.
        let net = tx(
            &[(2, W, HNET_MINT, "1000000"), (1, OTHER, HNET_MINT, "99")],
            &[(3, W, HNET_MINT, "51004213"), (1, OTHER, HNET_MINT, "0")],
        );
        assert_eq!(want(&net), Ok(()));
    }

    #[test]
    fn the_rpc_request_asks_for_a_finalized_transaction_of_any_version() {
        let r: serde_json::Value = serde_json::from_str(&get_transaction_request("5xyz")).unwrap();
        assert_eq!(r["method"], "getTransaction");
        assert_eq!(r["params"][0], "5xyz");
        assert_eq!(r["params"][1]["commitment"], "finalized");
        assert_eq!(r["params"][1]["maxSupportedTransactionVersion"], 0);
    }

    #[test]
    fn a_claim_never_prints_its_token_or_transaction() {
        let c = ClaimRequest {
            token: "secret-token".into(),
            signature: "5xyzSignature".into(),
        };
        let shown = format!("{c:?}");
        assert!(!shown.contains("secret-token") && !shown.contains("5xyz"));
    }
}
