# Buying passes from the browser (HidraVPN 0.1.3, HidraNet Browser 1.1.1)

Until 0.1.3 the only way to buy passes was the command line, as
administrator (`hidravpn passes buy`, then `passes claim`). A person who
uses only the browser could not buy any, and so could not use the VPN: both
exits admit only with a pass. The VPN page now buys through the service, in
Settings, Passes, "Buy passes with HNET". This is a port of review PR #25
(branch `review/hnet-checkout`) to the code of 0.1.2.

## What the page can do, and what it cannot

The page talks to the service with one command, `checkout`, and four
actions (`hidravpn-service/src/checkout.rs`):

- `status`: the order kept on this computer, if any. Nothing is sent
  anywhere.
- `packs`: what the issuer sells (`GET /packs`), without the account.
- `buy` with a pack (`passes`) and, to replace an open order,
  `replace_unpaid`: the person's word that they have not paid it.
- `claim` with the signature of the transaction that paid the order.

Nothing else the page sends is read. The browser builds the command afresh
from those fields (`vpn-manager.js` `checkout`), and the service ignores any
other field of a request. So the page can never name the wallet to pay, the
token, the price, the issuer or the account token:

- the wallet and the mint are the ones the signed node list names, through
  `passes::selling_issuer` and `check_answer`, the same path as
  `passes buy` (an issuer that asks for another wallet or token gets no
  order, and the person is told to pay it nothing);
- the issuer is the one the pocket's list names;
- the account token is the one the service keeps root-only beside the
  pocket (made by the service for the first purchase, as `passes buy` makes
  it); it never crosses the control channel, and no answer repeats it or a
  transaction signature.

The browser never sends money. The person pays from their own Solana wallet,
and the page never asks for the wallet's secret words.

Any account that may drive the service may buy, as with Get passes: what is
bought goes on the account this computer keeps. Replacing the account token
stays root's (`passes token`).

## Privado

An order carries the account token's hash and a claim the token: both are
refused by the service while two hops are up, with the command line's
reason (`passes::NOT_THROUGH_TWO_HOPS`), checked under the pocket's locks
(`checkout::refused_now`). Reading the order kept and the packs, which
carry no account, are not refused, as `passes list` and `passes buy` with
no count are not. The page also turns the packages and Check payment off
while two hops are up. Rapido and disconnected are allowed.

## The order on screen

A tester sent "5.99" instead of 149563.032846 HNET: the order showed the
dollar price beside the amount. The page now shows:

- "Send exactly", then the amount alone, large, with its own Copy, which
  copies only the digits, then "HNET";
- the receiving wallet, with its own Copy;
- the deadline, local time and UTC; past it the amount is no longer shown,
  and the page says not to pay it now;
- a warning that the amount must match to the last digit, that a dollar
  figure is only a reference never to be typed into the wallet, and to
  choose HNET in the wallet, not dollars;
- after all that, smaller: the dollar price and the rate, "for reference
  only", and the mint.

The packages list the price in HNET first; a dollar price follows on a line
of its own, smaller, as a reference, and the page says the exact amount
comes with the order.

The command line says the same: `passes buy N` prints the amount on a line
of its own, digits only, then the wallet, and the dollars after, as a
reference not to be typed into the wallet; `passes buy` lists each pack's
price in HNET with its dollar price on the next line.

## Orders are resumed, not replaced

An order open on this computer is shown again whenever the drawer opens. A
package chosen while one is open answers that order and asks the issuer
nothing; it is replaced only when the person ticks "I have not paid this
order". A quote the service refuses (another wallet or token, an amount that
does not add up, a deadline past or unreadable) replaces no order kept. An
order the signed list no longer stands behind is shown as not to be paid,
and is not claimed.

## What a claim says

The issuer's answer is compared with the reasons it is known to give, and
said in the service's own words; the issuer's text is never repeated (an
issuer able to write on the payment screen could tell people to pay
elsewhere). Every outcome but a confirmed one keeps the order:

- not final on chain yet: wait a minute, check the same signature again, do
  not pay again;
- the issuer busy: wait a few seconds, check again, do not pay again;
- refused (another amount, nothing to the wallet, a failed or older
  transaction, one already used): what it was, and not to pay again before
  checking that transaction in the wallet;
- no open order at the issuer, or too many tries: do not pay it; a payment
  made in time can still be credited by the operator;
- the issuer or the chain unreachable: try the same signature later, do not
  pay again;
- an earlier order's transaction: the open order stays open;
- confirmed: the passes credited and the balance at that moment; the order
  and the signature are cleared, and the page says to Get 10 passes per
  node.

## An older service

A 0.1.2 service does not know `checkout` and answers "unknown variant": the
browser reports it as `older`, and the page says buying needs a newer
HidraVPN and to update it from Settings, Service, Check for an update. The
rest of the page works as before. Checked against a 0.1.2 service built
from its release commit (c4be461).

## Release order

The browser's `MIN_VERSION` (`hidra-browser/src/main/vpn-installer.js`)
stays `0.1.2` in this change. Raise it to `0.1.3` at release time, once the
signed 0.1.3 manifest is published, so that Install and Check for an update
offer the version that has checkout. Until then a 1.1.1 browser with a 0.1.2
service says to update.

## Not part of this port

- The issuer-side hardening of PR #24 (`review/hnet-payments`: price feed,
  payment parsing, issuer recovery) is not needed by the checkout and is not
  ported.
- PR #25 blocked replacing the account token while an order is open; on main
  only root replaces the token, and the one replaced is kept beside it, so
  that rule is left out. An order claimed after the token changed is refused
  by the issuer, as it is from the command line.
- Buying is not anonymous: payments on Solana are public, and the issuer
  sees where the request comes from and can tie the payment to the pass
  account. The page says so. Purchases do not go through Tor.

## How to check it

```
cargo test --manifest-path hidravpn/Cargo.toml -p hidravpn-service checkout   # the service, with a stand-in issuer
hidravpn/scripts/test-pay-netns.sh      # the checkout through a real service, issuer and stand-in chain
hidravpn/scripts/test-refill-netns.sh   # refused while two hops are up, allowed in rapido
node hidra-browser/test/vpn-checkout.js # what crosses from the page to the service
xvfb-run -a hidra-browser/node_modules/.bin/electron --no-sandbox hidra-browser/test/vpn-checkout-electron.js   # the page
```
