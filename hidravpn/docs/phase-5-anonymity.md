# Phase 5 — what passes must not reveal

Phase 5 replaces open admission with **passes**: tokens bought with HNET and
spent at a node to be admitted. The plan is a Privacy Pass-style scheme of
blind signatures. This note says what the scheme must guarantee for
anonymity, and which questions are still open. Nothing here is built yet.
The decisions marked **[decide]** belong to the maintainers.

What phase 5 starts from (`anonymity.md`):

- Every node that admits openly is already shown a fresh key per connection.
  The exit of two hops is asked for it through the entry.
- Each such key is forgotten about ten minutes after the connection ends.

Admission is now paid for with a proof of work, not counted per address.
Passes replace that work with something a script with many machines cannot
cheaply make. They must not add a new identifier in its place.

## Requirements

1. **Unlinkable issuance and redemption.**
   - The issuer signs blinded tokens. The token a node later sees cannot be
     matched to the signing request that produced it: not by the issuer, not
     by the node, not by both together.
   - A token carries no serial, batch number, expiry or price tier that could
     narrow down who bought it, beyond what every token of the same kind
     shares.
   - If tokens come in kinds (a day, a month), each kind must have enough
     buyers to hide in. **[decide]** How many kinds, and whether a kind
     with too few buyers is withheld.
2. **No wallet address and no transaction ID anywhere near redemption.**
   - The node receives a token and a fresh WireGuard public key, nothing more.
   - The payment (an HNET transfer, visible on chain) is checked only by the
     issuer, only at issuance, and the issuer keeps no record tying a
     transaction to the blinded requests it signed.
   - No log on the issuer or a node names a wallet, a transaction, a token
     or a key. The same discipline as `hidravpn-core/src/logging.rs`, with a
     test in the style of `test-anonymity-netns.sh` F.
   - The client never sends a wallet address to a node, and never sends a
     token to the issuer.
3. **Redemption through the entry.** A pass for an exit is redeemed exactly
   as admission works now: through the entry, with a fresh key
   (`circuit::admit_behind`). The exit sees the entry's address, the token and
   the key, and nothing it could tie to the person.
4. **Double spending fails, even at two nodes at once.**
   - A token spent at node A must be refused at node B, even if both requests
     arrive in the same second.
   - That needs one place that records spent tokens, checked and written in
     one step (an atomic check-and-insert): a spent-token service run by the
     issuer, or a shared log the nodes write to. The record holds the token's
     hash only, never the key, the node or the time beyond what is needed to
     expire it.
   - A node that cannot reach that record refuses rather than admits.
   - **[decide]** Where the spent-token record lives, and who runs it. It
     learns *when* tokens are spent and *at which node*. If the issuer runs
     it, the issuer learns spending times, so the timing defences below
     matter.
5. **No new correlation through the token.** A token is spent once, for one
   connection's admission. Rotation and new identity spend a new one.
   **[decide]** whether one token admits one connection or a time window,
   such as an hour: a window means fewer tokens but reuse within the window,
   which an exit could link.

## Timing between paying and connecting

The payment is public on chain: an amount, a time, a wallet. If a wallet
buys one pass and a connection redeems one a minute later, timing alone
links them, however blind the signature. Mitigations, from strongest:

- **Buy in batches, spend later.** The client buys many tokens at once (a
  month's worth), keeps them, and redeems them one at a time over the
  following weeks. The purchase time then says nothing about any one
  connection.
- **Delay the first use.** A freshly bought batch is not used for some
  random time (hours), so a buyer's first connection does not follow the
  purchase. **[decide]** The default delay, and whether a person in a hurry
  may skip it, with a warning.
- **Fixed amounts.** Batches come in a few fixed sizes, so the amount on
  chain says nothing about how much the person uses.
- **Pay from a fresh wallet.** HNET transfers are linkable on chain. The
  client should say so plainly, and should not reuse the wallet it uses for
  anything else. **[decide]** Whether the browser's wallet makes a fresh
  address for each purchase.
- **Issuance over Tor.** The client asks the issuer for signatures through
  Tor, as the browser already fetches the node list, so the issuer does not
  learn the buyer's address.

Even with all of this, a party that sees the payment *and* the exit's
admissions *and* the entry's traffic can still try to match volumes over
weeks. The passes remove the per-connection link; they do not remove the
residue of watching every side at once.

## Questions for the maintainers

1. Token kinds and sizes: the anonymity-set floor (requirement 1).
2. Where the spent-token record lives, and who runs it (requirement 4).
3. One token per connection, or per window (requirement 5).
4. The default delay between buying and first use, and whether it can be
   skipped.
5. A fresh wallet address per purchase.
6. Every open node already gets a key per connection, paid for with a proof
   of work (`anonymity.md`, findings 11 and 12). The question left is
   whether passes replace the proof of work everywhere, or sit beside it.
