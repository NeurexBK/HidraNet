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
  `replace_unpaid`: the person's word that they have not paid it, naming
  the order on their screen by its amount in raw units (`amount_raw`, as
  digits). The service replaces the order it keeps only when that is the
  one; otherwise (an order opened meanwhile from the command line or
  another window) it answers the order kept, as already open.
- `claim` with the signature of the transaction that paid the order.

Nothing else the page sends is read. The browser builds the command afresh
from those fields (`vpn-manager.js` `checkout`), and the service ignores any
other field of a request. So the page can never name the wallet to pay, the
token, the price, the issuer or the account token:

- the wallet and the mint are the ones the signed node list names, through
  `passes::selling_issuer` and `check_answer`, the same path as
  `passes buy` (an issuer that asks for another wallet or token gets no
  order, and the person is told to pay it nothing);
- the issuer is the one the pocket's list names, and a claim goes only to
  it: an order kept from another issuer than the list names now is not to
  be paid and is not claimed (`passes::check_order`, so `passes claim`
  holds to it too);
- HNET is read with HNET's 6 decimals: a quote, packs or a kept order in
  HNET with other decimals is refused, or not to be paid;
- the account token is the one the service keeps root-only beside the
  pocket (made by the service for the first purchase, as `passes buy` makes
  it); it never crosses the control channel, and no answer repeats it or a
  transaction signature. An order keeps the SHA-256 of the token it was
  opened for (`order.json`, root-only; none in an order kept before); the
  claim goes with that token, whether it is the one kept now or one a newer
  token replaced and that is kept beside it, as `passes claim` does. When
  none here is that token, nothing is sent, and the person is told the
  order must be claimed with the token it was opened under. Neither a token
  nor its hash reaches the page or the service's log.

The browser never sends money. The person pays from their own Solana wallet,
and the page never asks for the wallet's secret words.

Any account that may drive the service may buy, as with Get passes: what is
bought goes on the account this computer keeps. Replacing the account token
stays root's (`passes token`).

## Privado

An order carries the account token's hash and a claim the token: both are
refused by the service while two hops are up, with the command line's
reason (`passes::NOT_THROUGH_TWO_HOPS`), checked under the pocket's locks
(`checkout::refused_now`). Asking for the packs is refused then too, though
it carries no account: buying goes no further in privado, so it is not
offered. Reading the order kept, which asks nothing of anyone, is not
refused. The page turns Show packages, the packages and Check payment off
while two hops are up, and says why where buying is, not only in a
tooltip. Rapido and disconnected are allowed.

## The order on screen

A tester sent "5.99" instead of 149563.032846 HNET: the order showed the
dollar price beside the amount. The page now shows:

- "Send exactly", then the amount alone, large, with its own Copy, which
  copies only the digits, then "HNET";
- the receiving wallet, with its own Copy;
- the deadline, "Pay before HH:MM on D Mon YYYY, your time (HH:MM UTC)",
  to the minute, rounded down;
- an order at or past its deadline, or with none that reads as a time, has
  a state of its own (`past_deadline`): the service gives no amount and no
  wallet for it and says "Its deadline has passed: do not pay it. If you
  paid it before the deadline, check that transaction below; if you did
  not, tick the box and choose a package." Its payment can still be
  checked. A deadline that passes while the order is on screen makes the
  page drop what it said and ask the service again, so "Pay it" is never
  beside "deadline has passed";
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
order the signed list no longer stands behind (another wallet, token or
issuer, or HNET in other decimals) is shown as not to be paid, and is not
claimed; the page adds that if it was paid, the transaction signature is
for the issuer's operator.

## What a claim says

The issuer's answer is compared with the reasons it is known to give, and
said in the service's own words; the issuer's text is never repeated (an
issuer able to write on the payment screen could tell people to pay
elsewhere). Every outcome but a confirmed one keeps the order:

- not final on chain yet: wait a minute, check the same signature again, do
  not pay again;
- busy: any 429 but the issuer's own too-many-tries reason
  (`payment::TOO_MANY_TRIES`, shared by the issuer and the client), so a
  proxy's rate limit in front of the issuer too: check the same signature
  again in a minute, do not pay again;
- refused (another amount, nothing to the wallet, a failed or older
  transaction, one already used): what it was, and not to pay again before
  checking that transaction in the wallet;
- no open order at the issuer, or too many tries (that exact reason only):
  do not pay it; a payment made in time can still be credited by the
  operator;
- the issuer or the chain unreachable: try the same signature later, do not
  pay again;
- an earlier order's transaction: the open order stays open;
- confirmed: the passes credited and the balance at that moment; the order
  and the signature are cleared, and the page says to Get 10 passes per
  node;
- no order kept on this computer (claimed already, from here or the command
  line): an answer with nothing to pay, saying "No order is open on this
  computer. If you just paid, it may already be credited: press Get 10
  passes per node before buying again, and do not pay again."

After any claim that is not confirmed, or whose answer is lost, the page
reads the order kept again and draws it from the service's answer, keeping
the claim's words; with no answer, it leaves no order on screen to pay.

An order refused by the issuer is said by what it means: 400, the package
is no longer sold (show the packages again); 404, the issuer sells no passes
right now; 429 with the issuer's reason for an account with as many orders
open as it may have (`payment::TOO_MANY_ORDERS`), pay the one you have or
wait for unpaid ones to lapse; any other 429, busy.

## Getting passes with none on the account

When Get 10 passes per node finds no account token on this computer, or the
issuer answers that it knows no account by that token or that none of its
passes is left (`pass::NOT_AN_ACCOUNT`, `pass::too_few_left(0, _)`, shared
by the issuer and the client), the service's answer carries the code
`no_passes`, and the page says "No passes on this computer's account yet.
Buy passes with HNET below, then press Get 10 passes per node." The page
reads the code, never the words.

## An older service

A 0.1.2 service does not know `checkout` and answers "unknown variant": the
browser reports it as `older`, and the page says buying needs a newer
HidraVPN and to update it from Settings, Service, Check for an update. The
rest of the page works as before. Once Install the update (or Install
HidraVPN) succeeds, the page forgets that the service was too old and asks
the new one for the order kept. Checked against a 0.1.2 service built from
its release commit (c4be461).

## Release order

The signed HidraVPN 0.1.3 manifest must be published on the site before
HidraNet Browser 1.1.1 is: a 1.1.1 browser with a 0.1.2 service says to
update, and Check for an update must then find 0.1.3.

The browser's `MIN_VERSION` (`hidra-browser/src/main/vpn-installer.js`)
stays `0.1.2` in this change. It is raised to `0.1.3` in the commit the
1.1.1 packages are built from, once that manifest is on the site, so that
Install and Check for an update offer the version that has checkout.

## Not part of this port

- The issuer-side hardening of PR #24 (`review/hnet-payments`: price feed,
  payment parsing, issuer recovery) is not needed by the checkout and is not
  ported.
- PR #25 blocked replacing the account token while an order is open; on main
  only root replaces the token, and the one replaced is kept beside it, so
  that rule is left out. The order remembers its token's hash instead, and
  the claim goes with that token while it is kept here (see above).
- Buying is not anonymous: payments on Solana are public, and the issuer
  sees where the request comes from and can tie the payment to the pass
  account. The page says so. Purchases do not go through Tor.

## How to check it

```
cargo test --manifest-path hidravpn/Cargo.toml -p hidravpn-service checkout   # the service, with a stand-in issuer
hidravpn/scripts/test-pay-netns.sh      # the checkout through a real service, issuer and stand-in chain
hidravpn/scripts/test-refill-netns.sh   # refused while two hops are up; in rapido an order opens
hidravpn/scripts/test-browser-netns.sh  # status, packs and an order through the browser's module, as a member of the group
node hidra-browser/test/vpn-checkout.js # what crosses from the page to the service
xvfb-run -a hidra-browser/node_modules/.bin/electron --no-sandbox hidra-browser/test/vpn-checkout-electron.js   # the page
```
