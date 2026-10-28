# HidraVPN — Phase 7: passes bought with HNET

Phase 5 made admission cost a pass and left the accounts to the maintainers'
hand: a token typed in, a daily quota. Now a pass can be bought: HNET sent on
Solana to a wallet of the operator's, and the pack credited to an account
nobody made by hand. It is built so that paying tells the issuer as little
as a hand-made account did, and tells a node nothing at all.

**Status:** built, tested against a stand-in for Solana's RPC, and used for
real purchases on the main network by the maintainers. The legal review
(MiCA) is still to come; this phase makes the mechanism, not the offer.

## How a purchase goes

1. `hidravpn passes buy` lists the packs the issuer sells (`GET /packs`).
2. `hidravpn passes buy 10` makes this machine's pass account token if it
   has none (32 random bytes, kept root-only at `/etc/hidravpn/pass.token`,
   as the issuer's own `account add` makes them), and asks the issuer for an
   **order** (`POST /quote`) with the token's SHA-256 and the pack. The
   issuer answers the exact amount to send: the pack's price plus a random
   tag in the last five decimals that no other open order has, so the amount
   names the order (50 HNET becomes, say, 50.042399). It also names the
   wallet, the mint and when the order lapses: two hours after it is made,
   unless a claim reaches it first, which keeps it open for 24 hours from
   when it was made (see "Flooding is slowed" below). The client checks the
   answer adds up, keeps it root-only at `/etc/hidravpn/order.json`, and
   prints what to send where, and to claim by then.
3. The person sends exactly that amount, from any Solana wallet. Nothing but
   the amount matters: no memo, no particular wallet, no form.
4. `hidravpn passes claim <signature>` (`POST /claim`, with the token and
   the transaction's signature). The issuer looks the transaction up at a
   Solana RPC, **finalized**, and reads what reached the wallet: the sum,
   over the wallet's token accounts for the mint, of each balance after less
   before. It must be the order's amount exactly, from a transaction that
   succeeded, with a block time not before the order was made (five minutes
   of slack for clocks), and a transaction never used before. Then the pack
   is credited to the account the token names — made on the spot, prepaid,
   under a name that says nothing (`paid-3fa1c0b2`) — and the order is
   closed. From then on `hidravpn passes get` and the automatic top-up work
   with that token like any other, drawing on a balance instead of a daily
   quota. A second purchase tops the same account up.

The issuer sells only when run with `--pay-wallet` (the receiving wallet's
public address; it holds no key for it) and at least one `--pay-pack
PASSES=PRICE`: the price in whole HNET (`10=50`; the tag takes the
decimals) or in dollars (`150=5.99usd`). `--pay-mint` and `--pay-decimals`
default to HNET's; `--pay-rpc` to Solana's public mainnet RPC, over HTTPS
(plain HTTP only to a private address, for tests). Give `--pay-rpc` more
than once to cross-check a payment across several independent RPCs: a
claim is credited only when a strict majority of them read the same
payment, so one lying or faulty RPC cannot conjure a payment out of
nothing (see "A payment no single RPC decides" below).

## A price in dollars, paid in HNET

A pack priced in dollars is turned into HNET at the **going rate** when the
order is opened, rounded to a whole HNET, and the amount is then fixed for
as long as that order is open (up to 24 hours). The rate comes from a
price feed the issuer fetches every five minutes (`--pay-price-every`): by
default the DEX screener's answer about the mint
(`api.dexscreener.com/tokens/v1/solana/<mint>`;
`--pay-price-url` for another, over HTTPS), reading the deepest pair whose
base is the mint. Give `--pay-price-url` more than once for redundancy:
each refresh tries the feeds in order and takes the first that answers, so
one being down does not stop dollar-priced sales (they must all speak the
same shape). `GET /packs` tells the HNET of the moment and the rate,
and the client shows both ("150 passes for 5.99 USD, 47217 HNET today").

A feed is a thing to be careful with: one that lies or glitches would sell
passes for nothing. So:

- **A move of more than 30 %** (`--pay-price-max-change`) since the last
  rate is **held**: the old rate goes on serving until the feed says the
  new one three times in a row (fifteen minutes at the default cadence).
  A real move gets through; a one-off wrong answer never sets a price.
- **A rate older than an hour** (`--pay-price-max-age`) is not used: the
  dollar-priced packs are off the list and an order for one is refused
  (503, "the going rate is not known right now") until the feed answers
  again. Packs priced in HNET sell on.
- The feed is read over HTTPS with the roots built in, the answer capped in
  size, and only `priceUsd` of a pair of the mint is taken.
- Every refresh is logged with the rate (public market data); a held move
  and a feed that did not answer are logged as warnings, so the operator
  sees what the issuer is doing.

What this does not protect against: a feed that is wrong and consistent for
fifteen minutes. The operator chooses the feed; a market that thin is the
operator's risk, as is the rate moving while an order is open.

## What protects the money

- **A payment seen on chain is of no use to anyone else.** Every transaction
  on Solana is public, amount and all. To claim one, you need the token whose
  hash made the order; a watcher has the amount and nothing else. One who
  opens an order of their own for the same pack gets another tag, so the
  amount is not theirs. Someone who sends an older transaction of the right
  amount is refused: it is from before the order. The test does all three.
- **A transaction pays once.** The issuer keeps the SHA-256 of every
  signature that paid, and refuses it again (409); the same claim repeated
  by its own token answers "already claimed" with the balance as it stands,
  so a claim cut off by a crash loses nothing.
- **The amount must match to the last digit.** One unit short or over, and
  the claim is refused and says so; the order stays open to be paid
  properly. A payment of the right amount to a wrong wallet or in another
  token is "none of the token reached the wallet". A payment made in time
  and never claimed before its order lapsed is credited by hand (see "A
  lapsed order, credited by hand" below); an order paid twice by mistake
  is for the operator to credit by hand (`account add --prepaid N`, or a
  new order).
- **Nothing is credited before the chain says finalized**, and the
  transaction's own result must be success (`meta.err` null).
- **A payment no single RPC decides.** Given more than one `--pay-rpc`, a
  claim asks each in turn and is credited only when a strict majority read
  the identical payment — same amount, same block time. An RPC that lies
  (claims a payment that never happened, or a different amount) or is
  merely broken is outvoted: it cannot forge a credit, only, if enough go
  wrong at once, withhold one (503, "its RPCs did not agree", the order
  stays open to try again). A majority agreeing on a *rejection* passes the
  real reason through. One RPC is its own majority, so a one-RPC issuer
  behaves exactly as before — and still trusts that one; three or more you
  control is the configuration for real money. The agreement rule is a pure
  function with its own unit test.
- **The issuer holds no key to the wallet.** It only reads the chain. There
  is nothing on it that could move the money.
- **Flooding is slowed, and crowds no buyer out.** Quotes and claims each
  pass a token bucket for the whole issuer (30 and 20 at once, then 2 a
  second each). A share is spent only by a request that can do something:
  a quote that could open an order, a claim for a token that has one. A
  claim for a token with no order, or a quote for a token that already has
  its 5 orders open (or with the issuer full), is answered from an index of
  the orders file the issuer keeps in memory, without the file, the lock
  or the bucket, so any number of them leaves the buckets to buyers. At
  most 20 000 orders are open at once; 30 tries at claiming one token's
  orders before a new order is needed (each try is one lookup on the
  chain); 4 lookups at a time. The orders file is written only when
  something changed.
- **Orders for nobody's payment cannot fill the issuer.** A token is any
  32 random bytes, so a quote cannot be asked to prove anything about it:
  proof of the token, sent at the quote, would cost a flood nothing, since
  a throwaway token proves itself as well as a real one. What bounds the
  orders instead is how long one lives unclaimed: two hours. All the quotes
  the bucket lets through in two hours (30 + 2 × 7 200), plus the orders a
  claim holds open for longer (at most 4 000 at once), stay under the cap of
  20 000; the issuer checks the sum when it is built. Filling the issuer
  then takes outrunning its bucket, which the proxy in front limits per
  client (next section), where it took one quote every four seconds
  before. A claim that reaches an order — even one made too soon, before
  the chain finalized the payment — holds it open for its 24 hours, so a
  claim can be tried again; the order is still bound to the token's hash
  alone, and a watcher of the chain has nothing more to claim it with. The
  issuer learns nothing it did not: the token's hash, at the quote, and the
  token, at the claim.
- **Only JSON is read.** `/issue`, `/quote` and `/claim` are read only when
  sent with `Content-Type: application/json`, as every client always has;
  anything else is refused (415). A web page can make its visitors'
  browsers send text or a form to any address without asking first; a body
  declared JSON the browser must ask about first, and the issuer answers no
  such question. So no page can spend the buckets with other people's
  browsers.
- **Comparisons of hashes take the same time whatever the input**, as the
  accounts' do; the index in memory compares the same way.

## The TLS proxy in front: a limit per client

The issuer sees every request come from 127.0.0.1, the proxy; it never
learns a client's address, and should not. Its buckets are for the whole
issuer. A limit per client address can only be set at the proxy, and it
must be: without one, a single machine can take all of the quotes or the
claims the bucket lets through. With one, it takes many.

Limit `POST /quote` and `POST /claim` per client address, well under the
issuer's own rate of 2 a second: 20 a minute each, say, is many times what
a buyer needs (one quote, a few claims) and a sixth of the issuer's rate.
Leave `POST /issue` alone or generous: it spends no shared budget and needs
a real token. Remember that a client connected to HidraVPN reaches the
issuer through its exit node, so every connected client of an exit shares
that exit's address: give the exits' addresses a higher limit, or none.
And keep the proxy from logging addresses: the limit is counted in memory,
for its window, and nowhere else.

Caddy has no rate limit of its own; the `rate_limit` handler is a plug-in
(`github.com/mholt/caddy-ratelimit`), built in with
`xcaddy build --with github.com/mholt/caddy-ratelimit`. Then, with the host
name the node list gives as the issuer's:

```
{
	order rate_limit before reverse_proxy
}

passes.example.org {
	rate_limit {
		zone quote {
			match {
				method POST
				path /quote
			}
			key {remote_host}
			events 20
			window 1m
		}
		zone claim {
			match {
				method POST
				path /claim
			}
			key {remote_host}
			events 20
			window 1m
		}
	}
	reverse_proxy 127.0.0.1:8730

	# No access log: it would be the record of who bought and when.
	log {
		output discard
	}
}
```

A client over the limit is answered 429, and `hidravpn passes buy` or
`claim` says so; trying again a minute later works. To exempt the exits,
add `not remote_ip <their addresses>` to each `match`. With nginx, the same
is `limit_req_zone $binary_remote_addr zone=pay:1m rate=20r/m;` and a
`limit_req zone=pay burst=5;` in `location = /quote` and `location =
/claim`. The issuer reads no `X-Forwarded-For` or other header naming the
client, whatever the proxy sends.

## A lapsed order, credited by hand

An order that lapses unpaid leaves the open ones, and its amount is free for
another order; a record of it stays in the orders file for 7 days: the
token's hash, the pack, the amount, when it was made and when it lapsed, and
whether a claim had reached it. That is all it takes to credit a payment
that was made in time but never claimed — the person paid and came back
after two hours, or the issuer could not be reached for a day. At most
10 000 such records are kept; past that, the oldest go first, and the
records of orders no claim reached go before any a claim reached, so a flood
of orders for nobody never pushes out the record of one its owner tried to
claim.

A claim for such an order is told so (404, "this token's order lapsed
unpaid … give them the transaction's signature"), and the client keeps
`order.json`. The person sends the operator the transaction's signature;
nothing else, and never the token. The operator:

1. looks the transaction up on a Solana explorer: finalized, succeeded,
   exactly the amount, of the mint, to the receiving wallet; and notes its
   amount and block time (UTC);
2. `hidravpn-issuer order lapsed --amount 50.042399` shows the record of
   that amount, if one is kept, and the window it could be paid in: from
   five minutes before it was made to when it lapsed;
3. `hidravpn-issuer order credit --amount 50.042399 --signature <sig>
   --paid-at 2026-10-13T09:41:07Z` credits the pack to the account the
   order's token names (made on the spot, prepaid, if there is none) and
   records the transaction as used, so it pays nothing else. It refuses a
   transaction already used, a time outside every record's window, or an
   amount no record has; if two records could match (an amount reused, a
   window overlapping by the clock slack), it asks for `--token-sha256`.

The command does not look the transaction up itself: step 1 is the
operator's. What it guards is whose account is credited: always the one
whose token made the order, so a watcher of the chain who writes in about
someone else's payment gains nothing by it. It works on the same files as
the running issuer, under the same lock, and needs no restart. Run it as
the issuer's own user, whose files they are (`sudo -u hidravpn-issuer
hidravpn-issuer order lapsed`; the default paths are the unit's).

## What stays off the record

- The issuer's `orders.json` keeps the token's hash, the amount and the
  hash of the signature that paid, and for 7 days the token's hash, the
  amount and the times of an order that lapsed unpaid; `accounts.json` the
  token's hash and the balance. Neither holds a token, a signature, a wallet or a name of anyone.
  Both are root-only, written beside and renamed over.
- No log names the wallet, a transaction, an amount or a token: an order is
  logged as "order opened for 10 pass(es)", a credit as "order claimed: 10
  pass(es) credited", a refusal by its kind only ("claim refused:
  wrong-amount"). The test greps for every one of those strings.
- A node never hears of a payment: passes bought are blind-signed like any
  other, and `hidravpn_core::payment` is used by the issuer and the client
  only.
- What the issuer does learn: that the account whose token hashes to X paid
  with the transaction whose signature hashes to Y, and when. It cannot tell
  which node a pass was spent on, or when. What the chain shows everyone:
  that some wallet sent 50.042399 HNET to the receiving wallet. The two meet
  only at the issuer, and only as hashes. The client says so and tells the
  person to pay from a wallet used for nothing else.

## What this does not do, said plainly

- **It does not watch the market for the operator.** The issuer tracks the
  rate; whether 5.99 dollars is the right price is the operator's call, as
  is restarting with another `--pay-pack` when it is not.

- **It is not post-quantum.** The signatures Solana runs on (Ed25519), the
  blind signatures passes are made of (RSA, phase 5) and the TLS key
  exchange to the issuer (X25519) are all of today's cryptography. What a
  quantum computer could not undo here: the hashes (SHA-256) that stand in
  for tokens and signatures in the issuer's files. A hybrid post-quantum
  key exchange for the TLS to the issuer (X25519MLKEM768) is a matter of the
  TLS library's crypto provider; it is not in this phase.
- **A price in HNET stays what it was set to**, whatever the market does;
  a price in dollars follows the feed, with the brakes above. Either way,
  open orders keep the amount they were made at.
- **The browser has no button for it yet**: the command line only.
- **The public RPC is rate-limited** and run by someone else; an operator
  who sells in earnest runs or rents RPCs and gives `--pay-rpc` (one or,
  for the quorum below, several).
- **No single RPC decides a payment** once more than one is given: a claim
  is credited only when a strict majority agree on the same payment, so a
  lying or broken RPC is outvoted. With one RPC the issuer still trusts
  that one — run three or more you control, over HTTPS, for real money.

## Command lines

```
# the issuer, selling (a machine of the maintainers', behind a TLS proxy)
hidravpn-issuer run --key issuer-key.json \
    --pay-wallet <the receiving wallet's address> \
    --pay-pack 150=5.99usd                       # in dollars, at the going rate
    # --pay-pack 10=50 --pay-pack 30=140         # or in whole HNET
hidravpn-issuer account list                 # paid accounts show "N left (prepaid)"
hidravpn-issuer account add --name someone --prepaid 20   # a prepaid account by hand
hidravpn-issuer order lapsed [--amount 50.042399]          # orders that lapsed unpaid, kept 7 days
hidravpn-issuer order credit --amount 50.042399 --signature <sig> --paid-at <block time, UTC>
                                             # one of them, paid in time (checked on chain by hand)

# a client
sudo hidravpn passes buy                     # the packs
sudo hidravpn passes buy 10                  # an order: send exactly this much, here, by then
sudo hidravpn passes claim <signature>       # once paid
sudo hidravpn passes get --count 10          # as before; "the account has N left"
sudo hidravpn passes list                    # shows an open order, if any
sudo hidravpn passes buy 10 --replace        # a new order, leaving the open one claimable until it lapses
```

## How to check it

```
hidravpn/scripts/test-pay-netns.sh         # an issuer selling, a stand-in chain and feed, a client: 73 checks
cargo test --manifest-path hidravpn/Cargo.toml -p hidravpn-core -p hidravpn-issuer
```

`test-pay-netns.sh` proves, in three namespaces with `test/solana-rpc-stub.py`
standing in for the chain and `test/price-stub.py` for the feed: the issuer
sells only with a wallet and packs, refuses a price with decimals, an RPC
and a feed in the clear; `GET /packs` tells the packs, the one in dollars
in today's HNET with the rate; the rate up 10 % is taken at the next fetch,
doubled at once it is held and taken only once the feed insisted three
times, a feed down leaves the last rate serving until it is stale and then
the dollar pack off the list and its order refused, and a feed back puts it
on again; an order in dollars tells the HNET, the dollars and the rate, kept
with it; an order is the price plus a tag under 0.1 HNET, kept root-only
with the token made for it; a claim with no transaction, a failed one, one
unit short, one from before the order, one to another wallet and one in
another token are each refused and say why, and the order stays open; the
right one credits the pack, the account appears prepaid, `passes get` draws
on it and a request past it is refused; the node admits with a pass bought
this way; a second purchase tops the account up; the first payment again
pays nothing more, with the owner's token or another's; a watcher of the
chain cannot claim a payment without the token, nor with an order of their
own; a stray second payment is credited to nobody; the same claim again is
idempotent; an order is open two hours until a claim reaches it; sixty
claims for tokens with no order and sixty quotes for a token with its five
orders open are each answered without slowing anyone, and right after them
the owner's claim and a new buyer's quote go through; forty quotes for
throwaway tokens at once are slowed; a quote, a claim or an issuance sent
as text or a form is refused (415) and opens nothing; a lapsed order is
listed by `order lapsed`, and `order credit` credits it to the order's own
token for a payment made while it was open, and refuses a payment made
after, another amount, and the same transaction twice; and the issuer's
files and logs hold no token, transaction, amount, wallet or client.

Unit tests cover the rest: base58 against known vectors; amounts written
and read back with every decimal; packs in HNET and in dollars, at a rate
and without one; the feed's answer read (the deepest pair of the mint, both
shapes, nothing from nonsense); a move of the rate held and then taken, a
stale rate not used, an issuer selling in dollars against a stub feed; what
a transaction must show (the
exact amount, the mint, the wallet, success, the time, the decimals, a
closed account netted out, shapes that are not an answer); orders taking
amounts of their own, lapsing, paying once, undoing a mark; an order no
claim reached lapsing in two hours, one a claim reached keeping its day, an
order written before the shorter life keeping its day, at most 4 000 held
at once; the record of a lapsed order, credited by hand only for its amount
in its window, once, to its own token, kept 7 days and, past 10 000
records, the ones no claim reached dropped first; the index answering what
needs no file; floods of claims without orders and of quotes past a
token's limit leaving the buckets to a buyer; a request not declared JSON
refused before anything is spent; a prepaid account's balance and a
purchase topping it up; and the issuer end to end against a stub RPC,
including what `run` refuses.
