# Browser HNET checkout review

The VPN page obtains packages, creates a quote, resumes the saved order and
checks a transaction through the authenticated local service channel. The
service reuses the CLI payment functions and the issuer from the trusted
pocket. No recipient, price, issuer URL or account token can be supplied by
the page. The wallet transfer remains an explicit action in the user's
Solana wallet. The browser does not sign or send transactions.

An existing order is returned instead of silently replacing it. Replacement
requires the user's declaration that it has not been paid. Account-token
replacement is blocked while an order is saved; account changes and checkout
share the service and filesystem locks. Orders are recovered on reopening
the panel. Confirmation errors retain the order and instruct the user not to
pay again. Account credit shown after a successful claim is a snapshot, not
a continuously refreshed balance. Fetching node passes uses the existing
Get passes control and does not make another blockchain payment.

The UI distinguishes pending finalization, rejected payments, temporary
unavailability, earlier-order claims and confirmed credit. External error
text is not returned through the checkout API. Signature debug output is
redacted. The page retains its restrictive CSP and exact-page IPC gate.

Quote validation runs before writing the order: a wrong mint, malformed or
expired deadline cannot replace a saved browser order. The checkout bridge
regression test is included in the existing browser CI test list.

## Privacy boundary

No tunnel, DNS, kill-switch, Tor circuit or blind-signature implementation is
changed. Checkout reuses the existing service HTTP client and OS routing;
it does not automatically route purchases through Tor. The issuer can observe
the connection source IP and associate a public transaction with the pass
account. The UI explicitly discloses this. This review does not establish
anonymous purchases or certify the deployed VPN against all traffic leaks.

## Operational acceptance

On 2026-10-27, a read-only request to the public `/packs` endpoint confirmed
the supplied mint, six decimals, receiving wallet and 150-pass USD 5.99
package. Its market-converted HNET amount is intentionally not hardcoded.
The operator reports an earlier mainnet purchase on 2026-10-20; that is not
acceptance evidence for this new interface.

Before public use, the operator still needs to verify the deployed issuer
version, configure independent RPC providers, decide the final commercial
price/receiving wallet and rotate the issuer key/signed list before the
reported 2026-11-25 expiration. Server settings and funds were not changed.
This work does not perform legal review or claim that a real-money purchase
through the new interface has been homologated. The browser and local
service must both contain the checkout protocol; an older service reports
that checkout is unavailable.

No installer, release workflow, published download or production deployment
is part of this local change.

## Local verification

- VPN page checks: 59 passed, including the exact-page IPC gate and CSP.
- Checkout bridge test: invalid inputs rejected, extra URL/token fields
  discarded, and only explicitly allowed fields sent to the service.
- Headless Chromium with a simulated bridge: package selection, exact quote,
  pending confirmation, retry, confirmed credit and signature clearing passed.
  This test exercises the UI, not a real blockchain transaction.
- Product language check passed. Changed JavaScript files passed syntax checks.
- Windows Rust service library: 25 tests passed, including saved-order resume,
  invalid control-token refusal, signature redaction and HTTP claim states
  (404 pending, 402 rejected, 503 unavailable, 200 confirmed). Failure keeps
  the order; successful confirmation removes it. These are local fixtures,
  not a transaction against the production issuer.
- Replacement-quote regression covers a wrong mint, malformed deadline,
  expired quote and successful replacement while preserving the old order
  on refusal.
- IPC sender authorization: 80 checks passed, including refusal of checkout
  from unauthorized pages. Leak-test logic: 18 checks passed with simulated
  network observations. Anonymity-claims source checks passed; these are not
  live packet-capture tests.
- Changed Rust files passed rustfmt; git diff whitespace checks passed.
- Rust service Clippy passed for all targets with warnings treated as errors
  (`--locked --offline -p hidravpn-service --all-targets -- -D warnings`).
- Linux execution of this checkout change and real-payment acceptance remain
  pending. Earlier backend CI results do not validate these new commands.
