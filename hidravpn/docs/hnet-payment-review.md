# HNET payment review

This local change is limited to the existing HNET payment and pass issuer
implementation. It is not a release or deployment procedure.

## Payment persistence

New confirmed payments first persist an order with `credit_pending: true`.
The account balance and a receipt containing only the transaction hash,
account token hash and pass count are then persisted together. Clearing the
pending marker is the last write. A repeated claim finishes a pending credit
without asking the chain again: it already passed confirmation before the
pending record was created.

The account receipt makes recovery idempotent even if the process exits after
crediting the balance but before clearing the pending marker. Recovery returns
the current balance, including any passes already spent. Pending orders and
their used-transaction markers are retained until credit completes. Old paid
orders deserialize as complete, preventing historical purchases from being
credited again. Existing files remain readable by the upgraded issuer. Do not
run an older issuer against files written by this version: it does not know
the pending-credit protocol.

Starting the issuer with payments enabled automatically completes pending
credits before accepting new connections. A malformed pending record stops
startup instead of being ignored. A client can also recover by repeating its
claim. An unreadable credited account returns a temporary failure rather than
an invented zero balance.

Receipts are retained in the private accounts file. Their hashes remain
sensitive account metadata and require the same access controls and backup
policy as account balances. They contain no raw transaction signature,
payment wallet or account token.

## Validation and pricing

- Multiple RPC entries for the same host and port are rejected, including
  equivalent default-port and host-case spellings. This blocks duplicate
  endpoint votes; distinct addresses still require operator verification of
  provider independence.
- RPC diagnostics record fixed failure categories instead of remote messages
  that could echo a transaction signature or endpoint credentials.
- JSON-RPC answers need the expected protocol version, request identifier
  and result member. An unreadable answer cannot count as a missing payment.
- An interrupted price refresh clears an outstanding large-move candidate.
  All three confirmations must follow successful consecutive refreshes.
- Candidate confirmations are compared with the original candidate rather
  than a sequence that can drift away from it.
- Invalid numeric rates and clock rollback cannot create a fresh price.
- Price pairs need positive finite liquidity; an explicit non-Solana chain
  is rejected. This is structural validation, not independent verification
  of market prices.
- Duplicate receiver balance entries in a transaction are malformed, never
  extra credit.
- Payment order tags require at least one decimal, and amount/balance
  arithmetic fails on overflow instead of wrapping or silently saturating.
- Files written by the issuer are explicitly private on Windows (protected
  DACL for the owner, SYSTEM and administrators) and Unix (mode 0600),
  including reused temporary files. The access restriction precedes writes.

## Acceptance boundaries

Existing command-line purchase, claim and pass issuance interfaces are kept.
Real receiving wallets, pack prices, providers and operational keys are
operator settings, not invented by this change. No real payment, production
issuer launch, GitHub publication or public artifact replacement is performed.
The existing browser does not yet expose a purchase button; this review does
not represent a delivered browser checkout interface.

## Local verification on 2026-10-26

- Windows GNU toolchain: 79 core tests and 17 issuer tests passed.
- The issuer executable built successfully.
- HTTP smoke test against the actual issuer process passed: quote, payment
  confirmation with two agreeing RPCs and one faulty RPC, one-time credit,
  repeated claim, automatic pending-credit recovery on restart, and checks
  that persisted files and process logs contain no raw test token/signature.
- Clippy for both crates and all their targets passed with warnings denied.
- The existing Unix inode-based test is correctly gated to Unix. The issuer
  keeps SIGTERM support there and supports Ctrl+C on Windows. Linux namespace
  suites were not rerun in this local Windows environment.

No production purchase or live issuer deployment is claimed by these checks.

## Follow-up audit on 2026-10-26

Reviewed the local diff, payment journal write order, account file locking,
legacy deserialization, balance arithmetic, RPC envelope checks and rate
confirmation changes. Reran all 96 tests successfully and Clippy with warnings
denied. The working-tree whitespace check also passed.

Expanded and reran the external HTTP smoke harness: two RPCs first report an
incorrect payment amount. The issuer rejects the claim with a client error
and creates no payment receipt. Restoring the correct majority allows the
same claim to credit exactly once. Repeated claims and restart recovery still
return the same balance.

These results support the tested local backend behavior. The restart scenario
simulates a pending final journal write; it is not a physical power-loss or
filesystem fault test. Linux execution and operator-configured end-to-end
acceptance remain unverified. No new browser interface, installer change,
production configuration or publication was included in this audit.
