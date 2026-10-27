//! Browser checkout uses the same private account and order as the CLI.
//! Callers hold both pocket locks. No account token leaves this module.
use crate::passes;
use anyhow::{anyhow, Result};
use hidravpn_core::{payment, Pocket};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Status,
    Packs,
    Buy {
        passes: u32,
        #[serde(default)]
        replace_unpaid: bool,
    },
    Claim {
        signature: crate::ipc::Secret,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pack {
    pub passes: u32,
    pub amount: String,
    pub usd: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct View {
    pub state: String,
    pub order: Option<passes::Order>,
    pub packs: Option<Vec<Pack>>,
    /// Snapshot at the successful claim, not a live account balance.
    pub balance: Option<u32>,
    pub message: String,
}

pub async fn execute(pocket: &Pocket, path: &Path, action: Action) -> Result<View> {
    let mut view = View {
        state: "idle".into(),
        order: passes::load_order(path)?,
        packs: None,
        balance: None,
        message: String::new(),
    };
    if let Some(order) = &view.order {
        validate_order(order)?;
        view.state = "awaiting_payment".into();
    }
    match action {
        Action::Status => {}
        Action::Packs => {
            let catalog = passes::packs(pocket).await?;
            if catalog.mint != payment::HNET_MINT || catalog.decimals != payment::HNET_DECIMALS {
                return Err(anyhow!(
                    "the issuer is not selling HNET passes; no payment was opened"
                ));
            }
            payment::check_address(&catalog.wallet)?;
            view.packs = Some(
                catalog
                    .packs
                    .into_iter()
                    .filter(|p| p.passes > 0 && p.price_raw > 0)
                    .map(|p| Pack {
                        passes: p.passes,
                        amount: payment::amount_to_string(p.price_raw, catalog.decimals),
                        usd: p.usd_cents.map(payment::usd_to_string),
                    })
                    .collect(),
            );
        }
        Action::Buy {
            passes: count,
            replace_unpaid,
        } => {
            if count == 0 {
                return Err(anyhow!("choose a valid pass package"));
            }
            if view.order.is_some() && !replace_unpaid {
                view.message = "Your saved order is still available. Do not pay twice.".into();
                return Ok(view);
            }
            let (token, _) = passes::token_for_purchase(&path.with_file_name("pass.token"))?;
            view.order = Some(
                passes::buy_checked(pocket, path, &token, count, |order| {
                    validate_order(order)?;
                    if hidravpn_core::timefmt::rfc3339_to_unix(&order.expires)?
                        <= hidravpn_core::timefmt::now_unix()
                    {
                        return Err(anyhow!("the issuer returned an expired quote"));
                    }
                    Ok(())
                })
                .await?,
            );
            view.state = "awaiting_payment".into();
            view.message = "Order saved on this computer. Pay the exact amount before the deadline, then check your transaction.".into();
        }
        Action::Claim { signature } => {
            let order = view
                .order
                .as_ref()
                .ok_or_else(|| anyhow!("no saved order; reload the payment panel"))?;
            payment::check_signature(&signature.0)?;
            let token = passes::read_token(&path.with_file_name("pass.token"))?;
            match passes::claim(path, order, &token, &signature.0).await {
                Ok(
                    passes::Claimed::Credited { balance, .. }
                    | passes::Claimed::AlreadyCredited { balance },
                ) => {
                    view.order = None;
                    view.balance = Some(balance);
                    view.state = "confirmed".into();
                    view.message = "Payment confirmed. Use Get passes to make your account credit available to the VPN nodes. No second payment is needed.".into();
                }
                Ok(passes::Claimed::EarlierOrder { balance, .. }) => {
                    view.balance = Some(balance);
                    view.state = "earlier_order".into();
                    view.message = "This transaction paid an earlier order. The current order remains open; do not repeat the earlier payment.".into();
                }
                Err(error) => {
                    // Never forward a remote response that could echo credentials.
                    if let Some(refusal) = error.downcast_ref::<passes::ClaimRefused>() {
                        view.state = if refusal.0 == 404 {
                            "pending"
                        } else if matches!(refusal.0, 429 | 500..=599) {
                            "unavailable"
                        } else {
                            "rejected"
                        }
                        .into();
                    } else {
                        view.state = "unavailable".into();
                    }
                    view.message = match view.state.as_str() {
                        "pending" => "The transaction is not finalized yet. Wait and check the same signature again. Do not pay again.",
                        "rejected" => "The issuer did not accept this transaction. Check the signature, exact amount, token, recipient and deadline. Your order is saved; do not send another payment without checking the first.",
                        _ => "Confirmation is unavailable. Your order is saved. Try the same signature again later; do not pay again.",
                    }.into();
                }
            }
        }
    }
    Ok(view)
}

fn validate_order(order: &passes::Order) -> Result<()> {
    if order.mint != payment::HNET_MINT
        || order.decimals != payment::HNET_DECIMALS
        || order.passes == 0
        || order.amount_raw == 0
        || payment::amount_from_string(&order.amount, order.decimals)? != order.amount_raw
    {
        return Err(anyhow!("the saved order is not a valid HNET purchase"));
    }
    payment::check_address(&order.wallet)?;
    hidravpn_core::timefmt::rfc3339_to_unix(&order.expires)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn invalid_replacement_quotes_preserve_the_saved_order() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for (mint, expires) in [
                ("11111111111111111111111111111111", "2099-11-01T00:00:00Z"),
                (payment::HNET_MINT, "not-a-date"),
                (payment::HNET_MINT, "2000-01-01T00:00:00Z"),
                (payment::HNET_MINT, "2099-11-01T00:00:00Z"),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 8192];
                let _ = socket.read(&mut request).await.unwrap();
                let body = serde_json::json!({"passes":150,"amount":"6.000001",
                    "amount_raw":6000001,"decimals":6,"mint":mint,
                    "wallet":"11111111111111111111111111111111","expires":expires})
                .to_string();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let dir = std::env::temp_dir().join(format!("hidra-checkout-quote-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pocket.json");
        let order = passes::Order {
            passes: 150,
            amount: "5.000001".into(),
            amount_raw: 5_000_001,
            decimals: 6,
            mint: payment::HNET_MINT.into(),
            wallet: "11111111111111111111111111111111".into(),
            expires: "2099-11-01T00:00:00Z".into(),
            issuer: url.clone(),
            usd: None,
            rate: None,
        };
        std::fs::write(
            passes::order_path(&path),
            serde_json::to_vec(&order).unwrap(),
        )
        .unwrap();
        let pocket = Pocket {
            pass_issuer: Some(hidravpn_core::directory::PassIssuer { url, keys: vec![] }),
            ..Pocket::default()
        };
        for _ in 0..3 {
            assert!(execute(
                &pocket,
                &path,
                Action::Buy {
                    passes: 150,
                    replace_unpaid: true
                }
            )
            .await
            .is_err());
            assert_eq!(passes::load_order(&path).unwrap(), Some(order.clone()));
        }
        let view = execute(
            &pocket,
            &path,
            Action::Buy {
                passes: 150,
                replace_unpaid: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(view.order.unwrap().amount, "6.000001");
        assert_eq!(
            passes::load_order(&path).unwrap().unwrap().amount_raw,
            6_000_001
        );
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn checkout_rejects_a_bad_control_token_before_creating_an_account() {
        let dir = std::env::temp_dir().join(format!("hidra-checkout-auth-{}", std::process::id()));
        let path = dir.join("pocket.json");
        let daemon = crate::daemon::Daemon::with_pocket("control".into(), path.clone());
        let response = daemon
            .handle(
                crate::ipc::Request {
                    token: "wrong".into(),
                    cmd: crate::ipc::Command::Checkout {
                        action: Action::Buy {
                            passes: 150,
                            replace_unpaid: false,
                        },
                    },
                },
                Some(1),
            )
            .await;
        assert!(!response.ok);
        assert!(response.checkout.is_none());
        assert!(!path.with_file_name("pass.token").exists());
    }
    #[tokio::test]
    async fn http_claim_failures_keep_the_order_and_success_clears_it() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for status in [404, 402, 503, 200] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 8192];
                let _ = socket.read(&mut request).await.unwrap();
                let body = if status == 200 {
                    r#"{"passes":150,"balance":150,"amount_raw":5000001,"already_claimed":false}"#
                } else {
                    r#"{"error":"private-token private-signature"}"#
                };
                socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let dir = std::env::temp_dir().join(format!("hidra-checkout-http-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pocket.json");
        let order = passes::Order {
            passes: 150,
            amount: "5.000001".into(),
            amount_raw: 5_000_001,
            decimals: 6,
            mint: payment::HNET_MINT.into(),
            wallet: "11111111111111111111111111111111".into(),
            expires: "2099-11-01T00:00:00Z".into(),
            issuer: url,
            usd: None,
            rate: None,
        };
        std::fs::write(
            passes::order_path(&path),
            serde_json::to_vec(&order).unwrap(),
        )
        .unwrap();
        std::fs::write(path.with_file_name("pass.token"), "private-token").unwrap();
        for expected in ["pending", "rejected", "unavailable", "confirmed"] {
            let view = execute(
                &Pocket::default(),
                &path,
                Action::Claim {
                    signature: crate::ipc::Secret(payment::base58_encode(&[7; 64])),
                },
            )
            .await
            .unwrap();
            assert_eq!(view.state, expected);
            let output = serde_json::to_string(&view).unwrap();
            assert!(!output.contains("private-token") && !output.contains("private-signature"));
            assert_eq!(
                passes::load_order(&path).unwrap().is_none(),
                expected == "confirmed"
            );
            if expected == "confirmed" {
                assert_eq!(view.balance, Some(150));
            }
        }
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn saved_orders_resume_without_a_new_quote_or_account_token() {
        let dir = std::env::temp_dir().join(format!("hidra-checkout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pocket.json");
        let order = passes::Order {
            passes: 150,
            amount: "5.000001".into(),
            amount_raw: 5_000_001,
            decimals: 6,
            mint: payment::HNET_MINT.into(),
            wallet: "11111111111111111111111111111111".into(),
            expires: "2026-11-01T00:00:00Z".into(),
            issuer: "https://example.invalid".into(),
            usd: None,
            rate: None,
        };
        std::fs::write(
            passes::order_path(&path),
            serde_json::to_vec(&order).unwrap(),
        )
        .unwrap();
        let pocket = Pocket::default();
        let view = execute(
            &pocket,
            &path,
            Action::Buy {
                passes: 150,
                replace_unpaid: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(view.order, Some(order.clone()));
        assert!(!path.with_file_name("pass.token").exists());
        assert_eq!(
            execute(&pocket, &path, Action::Status).await.unwrap().order,
            Some(order)
        );
        assert!(execute(
            &pocket,
            &path,
            Action::Claim {
                signature: crate::ipc::Secret("bad".into())
            }
        )
        .await
        .is_err());
        assert!(passes::load_order(&path).unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn checkout_commands_do_not_print_transaction_signatures() {
        let action = Action::Claim {
            signature: crate::ipc::Secret("private-signature".into()),
        };
        assert!(!format!("{action:?}").contains("private-signature"));
        let request: crate::ipc::Request =
            serde_json::from_str(r#"{"token":"control","cmd":"checkout","action":"status"}"#)
                .unwrap();
        assert!(matches!(
            request.cmd,
            crate::ipc::Command::Checkout {
                action: Action::Status
            }
        ));
    }
}
