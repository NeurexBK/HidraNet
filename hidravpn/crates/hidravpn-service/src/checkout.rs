//! Buying passes from the browser's VPN page (`checkout` on the control
//! channel). The same account token, order file and checks as the command
//! line's `passes buy` and `passes claim` (`passes::packs`, `passes::buy`,
//! `passes::claim`): the wallet and the token paid are the ones the signed
//! node list names (`passes::selling_issuer`), and the issuer is the one the
//! pocket's list names. The page only picks a pack, asks for an order, shows
//! it, and sends back the signature of the transaction that paid it; no
//! field it can send names a wallet, a token, a price, an issuer or an
//! account. The browser never sends money: the person pays from their own
//! Solana wallet.
//!
//! The caller holds the pocket's locks, and refuses an order or a claim
//! while two hops are up, as the command line does (`refused_now`).
//!
//! Everything the page is told is this program's own words. An issuer's
//! answer is compared with the reasons this program knows an issuer gives
//! and never repeated: an issuer that could put words on the payment screen
//! could tell people to pay somewhere the signed list does not name. No
//! account token and no transaction signature leaves this module.

use std::path::Path;

use anyhow::{anyhow, Result};
use hidravpn_core::Pocket;
use serde::{Deserialize, Serialize};

use crate::ipc::Secret;
use crate::passes;

/// What the page asks for. Fields a request carries beyond these (a
/// wallet, a mint, an issuer, a price, a token) are not read.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// The order kept on this machine, if any. Nothing is sent anywhere.
    Status,
    /// What the issuer sells. Asks the issuer, without the account.
    Packs,
    /// Opens an order for the pack of `passes`. An order already open is
    /// answered instead, never replaced, unless `replace_unpaid`: the
    /// person said they have not paid it.
    Buy {
        passes: u32,
        #[serde(default)]
        replace_unpaid: bool,
    },
    /// Claims the open order with the transaction that paid it. Printed as
    /// "<redacted>": the signature ties a public payment to this machine.
    Claim { signature: Secret },
}

impl Action {
    /// Whether this sends the pass account to the issuer: an order carries
    /// the token's hash, a claim the token. The command line refuses both
    /// while two hops are up (`passes::TwoHopsRefuse::AccountToken`).
    pub fn sends_account(&self) -> bool {
        matches!(self, Self::Buy { .. } | Self::Claim { .. })
    }
}

/// Refuses an order or a claim while two hops are up, with the reason the
/// command line and `get_passes` give (`passes::NOT_THROUGH_TWO_HOPS`): the
/// request would leave through the exit. Reading the order kept, and the
/// packs, which carry no account, go ahead in any mode, as `passes list`
/// and `passes buy` with no count do.
pub fn refused_now(action: &Action, two_hops_up: bool) -> Result<()> {
    if two_hops_up && action.sends_account() {
        return Err(anyhow!("{}", passes::NOT_THROUGH_TWO_HOPS));
    }
    Ok(())
}

/// The answer to every action: where the purchase stands, and what to say.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct View {
    /// "idle" (no order), "awaiting_payment", "not_payable" (an order the
    /// signed list no longer stands behind), and after a claim
    /// "confirmed", "earlier_order", "pending" (not final on chain yet),
    /// "busy", "rejected" or "unavailable".
    pub state: String,
    /// The order kept on this machine; none once it is paid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<OrderView>,
    /// The answer to `packs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packs: Option<Vec<Pack>>,
    /// With `packs`: what they are paid in, and the going rate in dollars
    /// for one, when packs are priced in dollars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// After a claim that paid the order: the passes it credited, and the
    /// account's balance at that moment (not kept up to date).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credited: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<u32>,
    pub message: String,
}

/// An order as the page shows it. Nothing here comes from the issuer
/// unchecked: the wallet and the token are the signed list's, the amount is
/// written from the units it was checked against, the deadline and the
/// dollars only when they read as a time and as numbers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderView {
    pub passes: u32,
    /// The exact amount to send, every decimal, digits and a point only;
    /// empty, as `wallet` is, for an order not to be paid.
    pub amount: String,
    /// "HNET", or "the token <mint>" for another one the list names.
    pub token: String,
    pub mint: String,
    pub wallet: String,
    /// RFC 3339, UTC; empty when the order kept does not say one.
    pub expires: String,
    /// For a pack priced in dollars: the price and the rate it was turned
    /// into the token at. A reference, never the amount to send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// False for an order not to be paid: one the signed list no longer
    /// stands behind (`passes::check_order`), or one that does not add up.
    pub payable: bool,
}

/// A pack for sale, as the page lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pack {
    pub passes: u32,
    /// The listed price in the token; an order adds a small tag to it.
    pub price: String,
    /// The price in dollars, for a pack priced so: a reference only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<String>,
}

const RESUMED: &str = "An order is open on this computer. Pay it, or, if you already paid, check its transaction below. Do not pay it twice.";
const ALREADY_OPEN: &str = "An order is already open on this computer, shown below. Pay it, or check the transaction that paid it. Replace it only if you have not paid it.";
const NOT_PAYABLE: &str = "The order kept on this computer asks for payment to a wallet, or in a token, the signed node list does not name, or it does not add up. Do not pay it. If you have not paid it, replace it with a new order.";
const OPENED: &str = "Order saved on this computer. Send exactly the amount shown, every decimal, to the wallet shown, before the deadline. Then paste the transaction's signature below and check the payment.";
const PENDING: &str = "The transaction is not on chain as finalized yet; that takes under a minute. Wait, then check the same signature again. Do not pay again.";
const BUSY: &str = "The pass issuer is busy right now. Wait a few seconds, then check the same signature again. Do not pay again.";
const UNAVAILABLE: &str = "The payment could not be confirmed right now: the pass issuer could not be reached, or could not ask the chain. Your order is kept. Check the same signature again in a few minutes. Do not pay again.";
const KEPT: &str = "Your order is kept on this computer. Do not pay again before you have checked that transaction in your wallet: the amount, the token and the receiving wallet.";
const NO_ORDER_THERE: &str = "The pass issuer has no open order for this computer's account: it lapsed, or was never made. Do not pay this order. If you paid it before it lapsed, keep the transaction's signature: the issuer's operator can still credit it by hand for a few days.";
const TOO_MANY_TRIES: &str = "This order was checked too many times, and the pass issuer takes no more claims for it. Do not pay it. If you paid it, keep the transaction's signature for the issuer's operator; if you did not, replace it with a new order.";
const PACKS_FAILED: &str = "The pass issuer could not be asked what it sells right now. Nothing was paid; try again later.";
const QUOTE_FAILED: &str =
    "The pass issuer could not open an order right now. Nothing was paid; try again later.";
const QUOTE_BUSY: &str = "The pass issuer is busy. Wait a moment and try again. Nothing was paid.";
const QUOTE_NOT_NOW: &str = "The pass issuer cannot sell this package right now; for a package priced in dollars, the going rate may not be known yet. Try again in a few minutes. Nothing was paid.";
const QUOTE_NO_PACK: &str =
    "The pass issuer does not sell this package. Show the packages again. Nothing was paid.";
const NO_ORDER_HERE: &str = "No order is open on this computer. Choose a package first.";
const NOT_CLAIMED: &str = "The order kept on this computer is not claimed: it asks for payment to a wallet, or in a token, the signed node list does not name, or it does not add up. Do not pay it.";
const NOT_A_SIGNATURE: &str = "That is not a transaction signature. Paste the whole signature from the transaction's details in your wallet.";
const NO_TOKEN: &str = "No pass account token can be read on this computer, so the order cannot be claimed here. Nothing was sent.";
const NO_TOKEN_MADE: &str =
    "No pass account token could be read or made on this computer. Nothing was bought.";
const ORDER_UNREADABLE: &str = "The order kept on this computer cannot be read. Nothing was sent; an administrator can look at it with `hidravpn passes list`.";
const NO_PACK: &str = "Choose one of the packages.";
const PAST_DEADLINE: &str = "the pass issuer's order is already past its deadline, or does not say one (is this computer's clock right?); nothing to pay";

/// Does what the page asked. The order is read first: whatever is asked,
/// the answer shows the order kept.
pub async fn execute(pocket: &Pocket, pocket_path: &Path, action: Action) -> Result<View> {
    let kept = passes::load_order(pocket_path).map_err(|_| anyhow!(ORDER_UNREADABLE))?;
    let mut view = View::of(pocket, kept.as_ref());
    let token_path = pocket_path.with_file_name("pass.token");
    match action {
        Action::Status => {}
        Action::Packs => {
            let (issuer, _) = passes::selling_issuer(pocket).map_err(said)?;
            let token = passes::token_name(issuer.pay_mint());
            let p = passes::packs(pocket)
                .await
                .map_err(|e| told(e, PACKS_FAILED, |_| None))?;
            view.packs = Some(
                p.packs
                    .iter()
                    .filter(|k| k.passes > 0 && k.price_raw > 0)
                    .map(|k| Pack {
                        passes: k.passes,
                        price: passes::price_to_string(k.price_raw, p.decimals),
                        usd: k.usd_cents.map(hidravpn_core::payment::usd_to_string),
                    })
                    .collect(),
            );
            view.token = Some(token);
            view.rate = p.rate.as_deref().and_then(number);
        }
        Action::Buy {
            passes: count,
            replace_unpaid,
        } => {
            if count == 0 {
                return Err(anyhow!(NO_PACK));
            }
            if view.order.is_some() && !replace_unpaid {
                if view.state == "awaiting_payment" {
                    view.message = ALREADY_OPEN.into();
                }
                return Ok(view);
            }
            // As the command line: from a list that names no wallet,
            // nothing is bought and no token is made.
            passes::selling_issuer(pocket).map_err(said)?;
            let (token, made) =
                passes::token_for_purchase(&token_path).map_err(|_| anyhow!(NO_TOKEN_MADE))?;
            let order = passes::buy_checked(pocket, pocket_path, &token, count, deadline_ahead)
                .await
                .map_err(|e| told(e, QUOTE_FAILED, quote_refused))?;
            view = View::of(pocket, Some(&order));
            view.message = if made {
                format!("{OPENED} The passes go on a pass account made for this computer now, kept by the service where only an administrator can read it.")
            } else {
                OPENED.into()
            };
        }
        Action::Claim { signature } => {
            let order = kept.ok_or_else(|| anyhow!(NO_ORDER_HERE))?;
            if !payable(pocket, &order) {
                return Err(anyhow!(NOT_CLAIMED));
            }
            hidravpn_core::payment::check_signature(&signature.0)
                .map_err(|_| anyhow!(NOT_A_SIGNATURE))?;
            let token = passes::read_token(&token_path).map_err(|_| anyhow!(NO_TOKEN))?;
            match passes::claim(pocket, pocket_path, &order, &token, &signature.0).await {
                Ok(passes::Claimed::Credited { passes, balance }) => {
                    view = View::of(pocket, None);
                    view.state = "confirmed".into();
                    view.credited = Some(passes);
                    view.balance = Some(balance);
                    view.message = format!(
                        "Payment confirmed: {passes} passes are on this computer's pass account, {balance} in all at this moment. Nothing more to pay. Get passes for the nodes now (Get 10 passes per node)."
                    );
                }
                Ok(passes::Claimed::AlreadyCredited { balance }) => {
                    view = View::of(pocket, None);
                    view.state = "confirmed".into();
                    view.balance = Some(balance);
                    view.message = format!(
                        "This transaction had already paid this order: nothing was counted twice, and the account has {balance} passes at this moment. Nothing more to pay. Get passes for the nodes now (Get 10 passes per node)."
                    );
                }
                Ok(passes::Claimed::EarlierOrder {
                    passes, balance, ..
                }) => {
                    view.state = "earlier_order".into();
                    view.balance = Some(balance);
                    view.message = format!(
                        "This transaction paid an earlier order, of {passes} passes, not the one shown, which stays open. Do not repeat that payment. The account has {balance} passes at this moment."
                    );
                }
                Err(e) => {
                    let (state, message) = claim_failed(&e);
                    view.state = state.into();
                    view.message = message;
                }
            }
        }
    }
    Ok(view)
}

impl View {
    /// Where things stand with `order` kept, before anything is asked.
    fn of(pocket: &Pocket, order: Option<&passes::Order>) -> Self {
        let order = order.map(|o| order_view(pocket, o));
        let (state, message) = match &order {
            None => ("idle", ""),
            Some(o) if o.payable => ("awaiting_payment", RESUMED),
            Some(_) => ("not_payable", NOT_PAYABLE),
        };
        Self {
            state: state.into(),
            order,
            packs: None,
            token: None,
            rate: None,
            credited: None,
            balance: None,
            message: message.into(),
        }
    }
}

/// Whether the order kept may be paid: the signed list stands behind it
/// (`passes::check_order`), and its amount is the units it says.
fn payable(pocket: &Pocket, o: &passes::Order) -> bool {
    passes::check_order(pocket, o).is_ok()
        && o.amount_raw > 0
        && o.passes > 0
        && hidravpn_core::payment::amount_from_string(&o.amount, o.decimals).ok()
            == Some(o.amount_raw)
}

fn order_view(pocket: &Pocket, o: &passes::Order) -> OrderView {
    let payable = payable(pocket, o);
    OrderView {
        passes: o.passes,
        amount: if payable {
            hidravpn_core::payment::amount_to_string(o.amount_raw, o.decimals)
        } else {
            String::new()
        },
        token: passes::token_name(&o.mint),
        mint: o.mint.trim().to_string(),
        // Not to be paid: no wallet to show.
        wallet: if payable {
            o.wallet.trim().to_string()
        } else {
            String::new()
        },
        expires: if hidravpn_core::timefmt::rfc3339_to_unix(&o.expires).is_ok() {
            o.expires.clone()
        } else {
            String::new()
        },
        usd: o.usd.as_deref().and_then(number),
        rate: o.rate.as_deref().and_then(number),
        payable,
    }
}

/// A figure from the issuer (dollars, a rate) only when it reads as a
/// plain decimal number: anything else is not shown.
fn number(s: &str) -> Option<String> {
    let s = s.trim();
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    let plain = match s.split_once('.') {
        Some((whole, frac)) => digits(whole) && digits(frac),
        None => digits(s),
    };
    (plain && s.len() <= 32).then(|| s.to_string())
}

/// A new order must say a deadline still ahead: one past it, or with none
/// that reads as a time, is not saved, and replaces no order kept.
fn deadline_ahead(o: &passes::Order) -> Result<()> {
    match hidravpn_core::timefmt::rfc3339_to_unix(&o.expires) {
        Ok(t) if t > hidravpn_core::timefmt::now_unix() => Ok(()),
        _ => Err(passes::PayRefused::error(PAST_DEADLINE)),
    }
}

/// A refusal worked out here from the signed list, said as it is.
fn said(e: anyhow::Error) -> anyhow::Error {
    match e.downcast_ref::<passes::PayRefused>() {
        Some(r) => anyhow!("{r}"),
        None => anyhow!("{QUOTE_FAILED}"),
    }
}

/// What the page is told when asking the issuer failed: a refusal worked
/// out here from the signed list (`passes::PayRefused`) as it is; an error
/// status of the issuer's in this program's words (`by_status`), or
/// `otherwise`; never the issuer's own words, nor a network error, which
/// can carry them.
fn told(
    e: anyhow::Error,
    otherwise: &str,
    by_status: fn(u16) -> Option<&'static str>,
) -> anyhow::Error {
    if let Some(r) = e.downcast_ref::<passes::PayRefused>() {
        return anyhow!("{r}");
    }
    let known = e
        .downcast_ref::<passes::IssuerRefused>()
        .and_then(|r| by_status(r.status));
    anyhow!("{}", known.unwrap_or(otherwise))
}

fn quote_refused(status: u16) -> Option<&'static str> {
    match status {
        404 => Some(QUOTE_NO_PACK),
        429 => Some(QUOTE_BUSY),
        503 => Some(QUOTE_NOT_NOW),
        _ => None,
    }
}

/// Where a claim the issuer did not take leaves things, in this program's
/// words: the issuer's reason is only compared with the ones it is known
/// to give. The order is kept in every case.
fn claim_failed(e: &anyhow::Error) -> (&'static str, String) {
    use hidravpn_core::payment::{Rejected, CLAIMS_BUSY, CLAIM_PACED};
    let Some(r) = e.downcast_ref::<passes::IssuerRefused>() else {
        // Not an answer of the issuer's: it could not be reached.
        return ("unavailable", UNAVAILABLE.into());
    };
    // Each reason a claim is refused for on chain, said as this program
    // says it.
    let paid_wrong = [
        Rejected::WrongAmount { paid_raw: 0 },
        Rejected::NoTransfer,
        Rejected::Failed,
        Rejected::TooEarly,
        Rejected::Decimals,
    ]
    .into_iter()
    .find(|x| r.reason == x.to_string());
    match (r.status, paid_wrong) {
        (404, _) if r.reason == Rejected::NotFound.to_string() => ("pending", PENDING.into()),
        (404, _) => ("rejected", NO_ORDER_THERE.into()),
        (429, _) if r.reason == CLAIM_PACED || r.reason == CLAIMS_BUSY => ("busy", BUSY.into()),
        (429, _) => ("rejected", TOO_MANY_TRIES.into()),
        (402, Some(Rejected::WrongAmount { .. })) => (
            "rejected",
            format!(
                "The pass issuer did not take this transaction: it paid another amount than this order's. The amount must match exactly, every decimal: a dollar figure, or a rounded amount, does not pay the order. {KEPT}"
            ),
        ),
        (402, Some(why)) => (
            "rejected",
            format!("The pass issuer did not take this transaction: {why}. {KEPT}"),
        ),
        (409, _) => (
            "rejected",
            format!("The pass issuer did not take this transaction: it already paid an order. {KEPT}"),
        ),
        (500..=599, _) => ("unavailable", UNAVAILABLE.into()),
        _ => (
            "rejected",
            format!("The pass issuer did not take this claim. {KEPT}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hidravpn_core::directory::PassIssuer;
    use hidravpn_core::payment::{Rejected, HNET_MINT};
    use tokio::io::AsyncWriteExt;

    const WALLET: &str = "So11111111111111111111111111111111111111112";
    const ELSEWHERE: &str = "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc";
    const TOKEN: &str = "private-account-token";

    fn selling(url: &str, wallet: Option<&str>) -> Pocket {
        Pocket {
            pass_issuer: Some(PassIssuer {
                url: url.into(),
                keys: Vec::new(),
                wallet: wallet.map(String::from),
                mint: None,
            }),
            ..Pocket::default()
        }
    }

    fn dir(what: &str) -> std::path::PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        let d = std::env::temp_dir().join(format!(
            "hidravpn-checkout-{what}-{}-{}",
            std::process::id(),
            u64::from_le_bytes(b)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn order(issuer: &str, amount: &str, raw: u64) -> passes::Order {
        passes::Order {
            passes: 150,
            amount: amount.into(),
            amount_raw: raw,
            decimals: 6,
            mint: HNET_MINT.into(),
            wallet: WALLET.into(),
            expires: "2099-11-01T00:00:00Z".into(),
            issuer: issuer.into(),
            usd: Some("5.99".into()),
            rate: Some("0.00004005".into()),
        }
    }

    fn keep(path: &Path, o: &passes::Order) {
        crate::daemon::write_private_atomic(
            &passes::order_path(path),
            serde_json::to_string(o).unwrap().as_bytes(),
        )
        .unwrap();
    }

    fn quote(wallet: &str, mint: &str, expires: &str) -> String {
        serde_json::json!({"passes": 150, "amount": "149563.032846", "amount_raw": 149_563_032_846u64,
            "decimals": 6, "mint": mint, "wallet": wallet, "expires": expires,
            "usd": "5.99", "rate": "0.00004005"})
        .to_string()
    }

    /// An issuer on this machine that answers each request with the next
    /// of `answers`, and says what it was asked: method, path and body.
    async fn issuer(
        answers: Vec<(u16, String)>,
    ) -> (
        String,
        tokio::task::JoinHandle<Vec<(String, String, String)>>,
    ) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let served = tokio::spawn(async move {
            let mut asked = Vec::new();
            for (status, body) in answers {
                let (mut s, _) = l.accept().await.unwrap();
                let r = hidravpn_core::admission::read_request(&mut s)
                    .await
                    .unwrap();
                asked.push((
                    r.method,
                    r.path,
                    String::from_utf8_lossy(&r.body).into_owned(),
                ));
                s.write_all(&hidravpn_core::admission::http_response(status, &body))
                    .await
                    .unwrap();
            }
            asked
        });
        (url, served)
    }

    /// A port that takes connections and counts them, answering nothing.
    async fn decoy() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while l.accept().await.is_ok() {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        (url, hits)
    }

    async fn ask(daemon: &crate::daemon::Daemon, json: serde_json::Value) -> crate::ipc::Response {
        let req: crate::ipc::Request = serde_json::from_value(json).unwrap();
        daemon.handle(req, Some(1000)).await
    }

    #[test]
    fn orders_and_claims_are_refused_while_two_hops_are_up_and_reading_is_not() {
        let buy = Action::Buy {
            passes: 150,
            replace_unpaid: true,
        };
        let claim = Action::Claim {
            signature: Secret("x".into()),
        };
        for a in [&buy, &claim] {
            let e = refused_now(a, true).unwrap_err().to_string();
            assert_eq!(e, passes::NOT_THROUGH_TWO_HOPS);
            assert!(e.starts_with("not while two hops (privado) are up"), "{e}");
            assert!(refused_now(a, false).is_ok());
        }
        for a in [Action::Status, Action::Packs] {
            assert!(!a.sends_account());
            assert!(refused_now(&a, true).is_ok() && refused_now(&a, false).is_ok());
        }
    }

    #[test]
    fn checkout_requests_parse_without_echoing_the_signature() {
        let action = Action::Claim {
            signature: Secret("private-signature".into()),
        };
        assert!(!format!("{action:?}").contains("private-signature"));
        let r: crate::ipc::Request =
            serde_json::from_str(r#"{"token":"t","cmd":"checkout","action":"status"}"#).unwrap();
        assert!(matches!(
            r.cmd,
            crate::ipc::Command::Checkout {
                action: Action::Status
            }
        ));
        let r: crate::ipc::Request = serde_json::from_str(
            r#"{"token":"t","cmd":"checkout","action":"buy","passes":150,"wallet":"x","mint":"y","issuer":"z","amount":"5.99"}"#,
        )
        .unwrap();
        assert!(matches!(
            r.cmd,
            crate::ipc::Command::Checkout {
                action: Action::Buy {
                    passes: 150,
                    replace_unpaid: false
                }
            }
        ));
        assert!(format!("{:?}", r).contains("Checkout"));
        for bad in [
            r#"{"token":"t","cmd":"checkout"}"#,
            r#"{"token":"t","cmd":"checkout","action":"pay"}"#,
            r#"{"token":"t","cmd":"checkout","action":"buy"}"#,
            r#"{"token":"t","cmd":"checkout","action":"claim"}"#,
        ] {
            assert!(
                serde_json::from_str::<crate::ipc::Request>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn the_wallet_and_the_issuer_are_the_signed_lists_whatever_the_page_sends() {
        let (url, served) = issuer(vec![(
            200,
            quote(WALLET, HNET_MINT, "2099-11-01T00:00:00Z"),
        )])
        .await;
        let (elsewhere_url, hits) = decoy().await;
        let d = dir("authority");
        let path = d.join("circuit.json");
        crate::daemon::save_pocket(&path, &selling(&url, Some(WALLET))).unwrap();
        let daemon = crate::daemon::Daemon::with_pocket("control".into(), path.clone());
        // The page names another wallet, mint, issuer, price and account:
        // none of it is read.
        let r = ask(
            &daemon,
            serde_json::json!({"token": "control", "cmd": "checkout", "action": "buy", "passes": 150,
                "wallet": ELSEWHERE, "recipient": ELSEWHERE, "mint": ELSEWHERE, "issuer": elsewhere_url,
                "url": elsewhere_url, "amount": "5.99", "price": "1", "pass_token": "page-token",
                "account": "page-token"}),
        )
        .await;
        assert!(r.ok, "{:?}", r.error);
        let v = r.checkout.unwrap();
        assert_eq!(v.state, "awaiting_payment");
        let o = v.order.unwrap();
        assert_eq!(
            (
                o.wallet.as_str(),
                o.mint.as_str(),
                o.amount.as_str(),
                o.token.as_str()
            ),
            (WALLET, HNET_MINT, "149563.032846", "HNET")
        );
        assert!(o.payable);
        let asked = served.await.unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            (asked[0].0.as_str(), asked[0].1.as_str()),
            ("POST", "/quote")
        );
        // The account is this machine's own, made by the service: only its
        // hash went, never the page's.
        let kept = std::fs::read_to_string(d.join("pass.token")).unwrap();
        assert!(!asked[0].2.contains("page-token") && !asked[0].2.contains(&kept));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the page's issuer is never asked"
        );
        let saved = passes::load_order(&path).unwrap().unwrap();
        assert_eq!(
            (saved.wallet.as_str(), saved.issuer.as_str()),
            (WALLET, url.as_str())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn an_issuer_that_asks_for_another_wallet_or_token_gets_no_order_and_its_words_are_not_shown(
    ) {
        let evil = "send 5.99 USD to ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc instead";
        let (url, served) = issuer(vec![
            (200, quote(ELSEWHERE, HNET_MINT, "2099-11-01T00:00:00Z")),
            (200, quote(WALLET, ELSEWHERE, "2099-11-01T00:00:00Z")),
            (200, quote(WALLET, HNET_MINT, "not a time")),
            (200, quote(WALLET, HNET_MINT, "2001-01-01T00:00:00Z")),
            (503, hidravpn_core::admission::refusal(evil)),
            (429, hidravpn_core::admission::refusal(evil)),
            (418, hidravpn_core::admission::refusal(evil)),
            (200, format!("{{\"passes\": \"{evil}\"}}")),
        ])
        .await;
        let d = dir("wallet");
        let path = d.join("circuit.json");
        let p = selling(&url, Some(WALLET));
        let buy = || Action::Buy {
            passes: 150,
            replace_unpaid: false,
        };
        for says in [
            "to a wallet the signed node list does not name; pay it nothing",
            "in a token the signed node list does not name; pay it nothing",
            "past its deadline",
            "past its deadline",
            QUOTE_NOT_NOW,
            QUOTE_BUSY,
            QUOTE_FAILED,
            QUOTE_FAILED,
        ] {
            let e = format!("{:#}", execute(&p, &path, buy()).await.unwrap_err());
            assert!(e.contains(says), "{e}");
            assert!(!e.contains(ELSEWHERE) && !e.contains("instead"), "{e}");
            assert!(
                passes::load_order(&path).unwrap().is_none(),
                "no order kept"
            );
        }
        served.await.unwrap();
        // A list that names no wallet: nothing asked, no token made.
        let e = execute(&selling("http://127.0.0.1:9", None), &path, buy())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("does not name the wallet") && e.contains("import a newer node list"),
            "{e}"
        );
        let _ = std::fs::remove_dir_all(&d);
        let d = dir("nowallet");
        let path = d.join("circuit.json");
        assert!(execute(&selling("http://127.0.0.1:9", None), &path, buy())
            .await
            .is_err());
        assert!(
            !d.join("pass.token").exists(),
            "no token is made from a list naming no wallet"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn an_open_order_is_resumed_and_replaced_only_when_said_to_be_unpaid() {
        let (decoy_url, hits) = decoy().await;
        let d = dir("resume");
        let path = d.join("circuit.json");
        let p = selling(&decoy_url, Some(WALLET));
        let kept = order(&decoy_url, "5.000001", 5_000_001);
        keep(&path, &kept);
        // Status and a buy without the person's word: the order kept,
        // nothing asked, no token made.
        let v = execute(&p, &path, Action::Status).await.unwrap();
        assert_eq!(v.state, "awaiting_payment");
        assert_eq!(v.message, RESUMED);
        let o = v.order.unwrap();
        assert_eq!(
            (o.amount.as_str(), o.wallet.as_str(), o.passes),
            ("5.000001", WALLET, 150)
        );
        assert_eq!(
            (o.usd.as_deref(), o.rate.as_deref()),
            (Some("5.99"), Some("0.00004005"))
        );
        assert_eq!(o.expires, "2099-11-01T00:00:00Z");
        for passes in [150, 10] {
            let v = execute(
                &p,
                &path,
                Action::Buy {
                    passes,
                    replace_unpaid: false,
                },
            )
            .await
            .unwrap();
            assert_eq!(v.state, "awaiting_payment");
            assert_eq!(v.message, ALREADY_OPEN);
            assert_eq!(v.order.unwrap().amount, "5.000001");
        }
        assert_eq!(passes::load_order(&path).unwrap(), Some(kept.clone()));
        assert!(!d.join("pass.token").exists());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        // A claim with something that is not a signature: refused here,
        // the order kept.
        std::fs::write(d.join("pass.token"), TOKEN).unwrap();
        let e = execute(
            &p,
            &path,
            Action::Claim {
                signature: Secret("not-a-signature".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(e.to_string(), NOT_A_SIGNATURE);
        assert_eq!(passes::load_order(&path).unwrap(), Some(kept.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        // With the person's word that it is unpaid, a new order replaces
        // it; one that is refused replaces nothing.
        let (url, served) = issuer(vec![
            (200, quote(ELSEWHERE, HNET_MINT, "2099-11-01T00:00:00Z")),
            (200, quote(WALLET, HNET_MINT, "2099-11-01T00:00:00Z")),
        ])
        .await;
        let p = selling(&url, Some(WALLET));
        let replace = || Action::Buy {
            passes: 150,
            replace_unpaid: true,
        };
        assert!(execute(&p, &path, replace()).await.is_err());
        assert_eq!(passes::load_order(&path).unwrap(), Some(kept));
        let v = execute(&p, &path, replace()).await.unwrap();
        assert_eq!(v.order.unwrap().amount, "149563.032846");
        assert_eq!(
            passes::load_order(&path).unwrap().unwrap().amount_raw,
            149_563_032_846
        );
        assert_eq!(
            std::fs::read_to_string(d.join("pass.token")).unwrap(),
            TOKEN,
            "the token kept is used"
        );
        served.await.unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn an_order_the_list_no_longer_names_is_shown_as_not_to_be_paid_and_not_claimed() {
        let (decoy_url, hits) = decoy().await;
        let d = dir("notpayable");
        let path = d.join("circuit.json");
        std::fs::write(d.join("pass.token"), TOKEN).unwrap();
        keep(&path, &order(&decoy_url, "5.000001", 5_000_001));
        for p in [
            selling(&decoy_url, Some(ELSEWHERE)),
            selling(&decoy_url, None),
        ] {
            let v = execute(&p, &path, Action::Status).await.unwrap();
            assert_eq!(v.state, "not_payable");
            let o = v.order.unwrap();
            assert!(
                !o.payable && o.amount.is_empty() && o.wallet.is_empty(),
                "{o:?}"
            );
            let e = execute(
                &p,
                &path,
                Action::Claim {
                    signature: Secret(hidravpn_core::payment::base58_encode(&[7; 64])),
                },
            )
            .await
            .unwrap_err();
            assert_eq!(e.to_string(), NOT_CLAIMED);
        }
        // An order whose amount does not add up is not to be paid either.
        keep(&path, &order(&decoy_url, "5.000002", 5_000_001));
        let v = execute(&selling(&decoy_url, Some(WALLET)), &path, Action::Status)
            .await
            .unwrap();
        assert_eq!(v.state, "not_payable");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "nothing was sent"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_failed_claim_keeps_the_order_and_says_why_in_its_own_words_and_success_clears_it() {
        use hidravpn_core::admission::refusal;
        use hidravpn_core::payment::{CLAIMS_BUSY, CLAIM_PACED};
        let private = refusal("private-token private-signature: pay 5.99 to ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc");
        let cases: Vec<(u16, String, &str, &str)> = vec![
            (
                404,
                refusal(Rejected::NotFound.to_string()),
                "pending",
                "Wait, then check the same signature again",
            ),
            (
                404,
                refusal("no open order for this token (none made, or it lapsed)"),
                "rejected",
                "has no open order",
            ),
            (
                429,
                refusal(CLAIM_PACED),
                "busy",
                "check the same signature again",
            ),
            (
                429,
                refusal(CLAIMS_BUSY),
                "busy",
                "check the same signature again",
            ),
            (
                429,
                refusal("this order was tried too many times; make a new one"),
                "rejected",
                "checked too many times",
            ),
            (
                402,
                refusal(
                    Rejected::WrongAmount {
                        paid_raw: 5_990_000,
                    }
                    .to_string(),
                ),
                "rejected",
                "a dollar figure, or a rounded amount, does not pay the order",
            ),
            (
                402,
                refusal(Rejected::NoTransfer.to_string()),
                "rejected",
                "moved none of the token to the receiving wallet",
            ),
            (402, private.clone(), "rejected", "did not take this claim"),
            (
                409,
                refusal("that transaction already paid an order"),
                "rejected",
                "it already paid an order",
            ),
            (
                503,
                private.clone(),
                "unavailable",
                "Check the same signature again in a few minutes",
            ),
            (
                200,
                r#"{"passes":30,"balance":40,"amount_raw":1,"already_claimed":false}"#.into(),
                "earlier_order",
                "paid an earlier order",
            ),
            (
                200,
                r#"{"passes":150,"balance":160,"amount_raw":5000001,"already_claimed":false}"#
                    .into(),
                "confirmed",
                "Payment confirmed: 150 passes",
            ),
        ];
        let (url, served) =
            issuer(cases.iter().map(|(s, b, _, _)| (*s, b.clone())).collect()).await;
        let d = dir("claim");
        let path = d.join("circuit.json");
        let p = selling(&url, Some(WALLET));
        let kept = order(&url, "5.000001", 5_000_001);
        keep(&path, &kept);
        std::fs::write(d.join("pass.token"), TOKEN).unwrap();
        let sig = hidravpn_core::payment::base58_encode(&[7; 64]);
        for (_, _, state, says) in &cases {
            let v = execute(
                &p,
                &path,
                Action::Claim {
                    signature: Secret(sig.clone()),
                },
            )
            .await
            .unwrap();
            assert_eq!(v.state, *state, "{v:?}");
            assert!(v.message.contains(says), "{state}: {}", v.message);
            let out = serde_json::to_string(&v).unwrap();
            for secret in [
                TOKEN,
                sig.as_str(),
                "private-token",
                "private-signature",
                ELSEWHERE,
            ] {
                assert!(!out.contains(secret), "{state}: {out}");
            }
            if *state == "confirmed" {
                assert!(v.order.is_none() && passes::load_order(&path).unwrap().is_none());
                assert_eq!((v.credited, v.balance), (Some(150), Some(160)));
            } else {
                assert_eq!(
                    passes::load_order(&path).unwrap(),
                    Some(kept.clone()),
                    "{state}"
                );
                assert!(v.order.is_some(), "{state}");
                if *state != "earlier_order" {
                    assert!(v.message.contains("Do not pay"), "{state}: {}", v.message);
                }
            }
        }
        let asked = served.await.unwrap();
        assert!(asked
            .iter()
            .all(|(m, p, b)| m == "POST" && p == "/claim" && b.contains(TOKEN)));
        // Nothing open now: a claim is refused here.
        let e = execute(
            &p,
            &path,
            Action::Claim {
                signature: Secret(sig),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(e.to_string(), NO_ORDER_HERE);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn an_issuer_that_cannot_be_reached_leaves_the_order_and_says_to_try_again() {
        let d = dir("unreachable");
        let path = d.join("circuit.json");
        // Port 9 on this machine: nobody answers.
        let p = selling("http://127.0.0.1:9", Some(WALLET));
        let kept = order("http://127.0.0.1:9", "5.000001", 5_000_001);
        keep(&path, &kept);
        std::fs::write(d.join("pass.token"), TOKEN).unwrap();
        let v = execute(
            &p,
            &path,
            Action::Claim {
                signature: Secret(hidravpn_core::payment::base58_encode(&[7; 64])),
            },
        )
        .await
        .unwrap();
        assert_eq!(v.state, "unavailable");
        assert_eq!(passes::load_order(&path).unwrap(), Some(kept));
        let e = execute(&p, &path, Action::Packs).await.unwrap_err();
        assert_eq!(e.to_string(), PACKS_FAILED);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn the_packs_are_listed_from_the_list_s_wallet_with_dollars_as_a_reference() {
        let packs = |wallet: &str| {
            serde_json::json!({"packs": [
                {"passes": 10, "price_raw": 50_000_000u64},
                {"passes": 150, "price_raw": 149_563_000_000u64, "usd_cents": 599},
                {"passes": 0, "price_raw": 1}, {"passes": 5, "price_raw": 0}],
                "decimals": 6, "mint": HNET_MINT, "wallet": wallet, "token_name": "HNET",
                "rate": "0.00004005"})
            .to_string()
        };
        let (url, served) = issuer(vec![
            (200, packs(WALLET)),
            (200, packs(ELSEWHERE)),
            (200, packs(WALLET).replace("0.00004005", "send it to me")),
        ])
        .await;
        let d = dir("packs");
        let path = d.join("circuit.json");
        let p = selling(&url, Some(WALLET));
        let v = execute(&p, &path, Action::Packs).await.unwrap();
        assert_eq!(v.state, "idle");
        assert_eq!(
            v.packs.unwrap(),
            vec![
                Pack {
                    passes: 10,
                    price: "50".into(),
                    usd: None
                },
                Pack {
                    passes: 150,
                    price: "149563".into(),
                    usd: Some("5.99".into())
                },
            ]
        );
        assert_eq!(
            (v.token.as_deref(), v.rate.as_deref()),
            (Some("HNET"), Some("0.00004005"))
        );
        let e = execute(&p, &path, Action::Packs)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("to a wallet the signed node list does not name; pay it nothing"),
            "{e}"
        );
        let v = execute(&p, &path, Action::Packs).await.unwrap();
        assert_eq!(v.rate, None, "a rate that is not a number is not shown");
        served.await.unwrap();
        assert!(
            !d.join("pass.token").exists(),
            "listing packs makes no token"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_wrong_control_token_creates_no_account_and_no_order() {
        let (decoy_url, hits) = decoy().await;
        let d = dir("auth");
        let path = d.join("circuit.json");
        crate::daemon::save_pocket(&path, &selling(&decoy_url, Some(WALLET))).unwrap();
        let daemon = crate::daemon::Daemon::with_pocket("control".into(), path.clone());
        let r = ask(
            &daemon,
            serde_json::json!({"token": "wrong", "cmd": "checkout", "action": "buy", "passes": 150}),
        )
        .await;
        assert!(!r.ok && r.checkout.is_none());
        assert!(!d.join("pass.token").exists() && passes::load_order(&path).unwrap().is_none());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        // The right one, and status: nothing open, said as such.
        let r = ask(
            &daemon,
            serde_json::json!({"token": "control", "cmd": "checkout", "action": "status"}),
        )
        .await;
        assert!(r.ok);
        assert_eq!(r.checkout.unwrap().state, "idle");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_plain_numbers_from_the_issuer_are_shown() {
        for ok in ["5.99", "0.00004005", "149563", "12.5"] {
            assert_eq!(number(ok).as_deref(), Some(ok));
        }
        for bad in [
            "",
            ".5",
            "5.",
            "5.99 USD",
            "-1",
            "1e9",
            "send it",
            "5,99",
            &"9".repeat(40),
        ] {
            assert_eq!(number(bad), None, "{bad}");
        }
    }
}
