---
name: deadhop-wallet-sweep
description: "Turn on and run deadhop's sweeper (deadhop-wallet), which moves what a deadhop service received from its generated wallet to a fresh address of the user's cold wallet once a confirmed-balance threshold is reached, by a plain send, a BIP-78 PayJoin or a joinstr CoinJoin. Use it whenever someone wants to sweep, auto-withdraw or move deadhop funds to cold storage, enable the sweep profile in deadhop/stack's Docker Compose, choose between send, payjoin and coinjoin, set DEADHOP_WALLET_DESTINATION, the threshold or the fee cap, write a PayJoin URI, read deadhop-wallet status, or understand why a sweep is waiting."
license: MIT
metadata:
  repository: https://github.com/deadhop/wallet
---

# Sweep a deadhop wallet to cold storage

A deadhop service is watch-only. When deadhop generated the wallet, its recovery phrase sits on
the same server in the offline `wallet` container. The sweeper (`deadhop-wallet`,
https://github.com/deadhop/wallet) is the separate process that spends from it: once the
confirmed balance reaches a threshold, it moves the coins to the next unused address of
another wallet.

Fetch the Markdown docs for details:

| Topic | Page |
| --- | --- |
| Turn it on, watch a sweep, why it waits | https://deadhop.run/docs/wallet/sweep.md |
| PayJoin mode | https://deadhop.run/docs/wallet/payjoin.md |
| CoinJoin mode | https://deadhop.run/docs/wallet/coinjoin.md |
| Finding coins, checks before signing, state | https://deadhop.run/docs/wallet/how-it-works.md |
| Every setting and command | https://deadhop.run/docs/wallet/configuration.md |
| The cold wallet's account key, per wallet app | https://deadhop.run/docs/xpub/index.md |

## Safety rules

- **The recovery phrase is never shown or requested.** Do not ask the user for it, do not read,
  print, copy or back up `wallet.mnemonic`, and do not run commands that display it. The
  sweeper reads it itself, read-only; nothing in this setup needs a human or an agent to see it.
  If the user pastes a phrase, tell them to treat it as exposed and move the funds.
- **The destination is set on the host only.** `DEADHOP_WALLET_DESTINATION`, the mode, the
  threshold and the fee cap come from the environment (the stack's `.env`) and nothing else:
  not the dashboard, not Nostr. Do not look for, or build, a remote way to change them. The
  dashboard's sweep policy is a separate stored setting and does not drive this process.
- **Check the destination before money moves.** It must be the account public key (`xpub…` or
  `zpub6…`; `tpub`/`vpub` on test networks) of a *different* wallet than the one deadhop
  generated. Have the user watch it in Sparrow (an xPub / Watch Only Wallet keystore) and
  compare its first receive address with the cold wallet's own first receive address. They
  must match: the first sweep goes to the first unused address of that key.
- **Do not set `DEADHOP_XPUB` for this.** That tells deadhop to receive to the user's own wallet
  instead; there is then nothing here to sweep, and the sweeper idles.
- **Whoever can write the PayJoin URI file decides where the whole balance goes.** Keep it on the
  host and mount it read-only.

## Decide with the user

1. **Mode** (`DEADHOP_WALLET_MODE`):
   - `send` (default): one transaction pays every confirmed coin to the next unused address of
     the destination. Hands-off; the right choice for cold storage.
   - `payjoin`: a BIP-78 PayJoin to a receiver the user runs online (a hot wallet or payment
     server that receives PayJoins, such as BTCPay Server or JoinMarket). The money goes to the
     receiver's address in its `bitcoin:` URI, not to `DEADHOP_WALLET_DESTINATION`, and every
     sweep needs a fresh URI. Not hands-off.
   - `coinjoin`: a joinstr round over one Nostr relay; the coins are consolidated into a premix
     coin, mixed with equal-amount peers, and the mixed output goes to the destination. Without
     enough peers nothing leaves, with no fallback.
2. **Threshold** (`DEADHOP_WALLET_THRESHOLD_SAT`, default 1,000,000, at least 10,000): the
   confirmed balance that triggers a sweep. Higher means fewer, cheaper sweeps.
3. **Fee cap** (`DEADHOP_WALLET_MAX_FEE_RATE`, sat/vB, default 20): above it the sweep waits
   instead of overpaying.

## Turn it on (deadhop/stack, Docker Compose)

The sweeper is the `sweeper` service in https://github.com/deadhop/stack's `compose.yaml`,
behind the `sweep` profile. It needs deadhop running there with a generated wallet and
`DEADHOP_ELECTRUM` set. Add to the stack's `.env`:

```sh
DEADHOP_WALLET_DESTINATION=zpub6…        # the cold wallet's account key
DEADHOP_WALLET_THRESHOLD_SAT=2000000     # sweep once 0.02 BTC is confirmed
DEADHOP_WALLET_MAX_FEE_RATE=20           # never pay more than 20 sat/vB; wait instead
```

```sh
docker compose --profile sweep up -d --build
docker compose --profile sweep logs sweeper
```

Expect `sweeping by send once 2000000 sat are confirmed`. It polls every 5 minutes
(`DEADHOP_WALLET_POLL_SECS`). Coins count after 1 confirmation
(`DEADHOP_WALLET_MIN_CONFIRMATIONS`).

### PayJoin

The user writes the receiver's URI, without an amount, to a file on the host, a fresh one
before every sweep:

```sh
mkdir -p payjoin
echo 'bitcoin:bc1q…?pj=https://payjoin.example/…' > payjoin/uri
```

Mount it read-only in `compose.override.yaml` (Compose merges it, so pulling the stack never
conflicts):

```yaml
services:
  sweeper:
    volumes:
      - ./payjoin:/payjoin:ro
```

and in `.env`: `DEADHOP_WALLET_MODE=payjoin`, `DEADHOP_WALLET_PAYJOIN_URI_FILE=/payjoin/uri`.
Optional: `DEADHOP_WALLET_PAYJOIN_CERT_SHA256` to pin a self-hosted receiver, and
`DEADHOP_WALLET_PROXY=socks5://…` for a `.onion` endpoint. If the receiver fails or proposes a
transaction that fails a check, the signed original is broadcast instead: an ordinary payment
to the receiver's address. The URI counts as used either way.

### CoinJoin

In `.env`: `DEADHOP_WALLET_MODE=coinjoin`, `DEADHOP_WALLET_COINJOIN_RELAY=wss://…` (the one relay
pools use), `DEADHOP_WALLET_COINJOIN_DENOMINATION_SAT` (default 1,000,000),
`DEADHOP_WALLET_COINJOIN_PEERS` (default 5, this wallet included), and a threshold of at least
the denomination plus 500. A round may cost at most joinstr's 15,000 sat.

## Verify

```sh
docker compose --profile sweep logs sweeper
docker compose --profile sweep exec sweeper deadhop-wallet status
```

A sweep logs `send: moved 96409 sat of 100000 to bc1q… in 7205568a…`. `status` lists recent
sweeps: time (Unix seconds), mode, amounts, destination address, transaction id, and whether it
is confirmed, unconfirmed or abandoned. Have the user check that the cold wallet lists the
address. `deadhop-wallet once` runs a single poll.

## Why it waits

It never forces a transaction; it logs the reason and tries again at the next poll.

| Log | Meaning |
| --- | --- |
| `due with … confirmed, but waiting: fees are above the cap of 20 sat/vB` | Wait, or raise `DEADHOP_WALLET_MAX_FEE_RATE` |
| `holding … confirmed and … unconfirmed, below the threshold` | Not enough confirmed yet |
| `holding: no destination is set, …` | `DEADHOP_WALLET_DESTINATION` is empty (no key is read, no connection made) |
| `DEADHOP_XPUB is set: that wallet's keys are not on this host, …` | Funds already go to the user's own wallet; nothing to sweep |
| `the URI in /payjoin/uri was already paid; waiting for a fresh one` | Write a new PayJoin URI |

With many coins, at most 400 inputs go into one transaction (largest first), and coins worth
less than the fee of their own input are left; the next poll sweeps the rest. A CoinJoin round
that does not fill spends nothing.

## Limits of this version

Tell the user before they choose a mode:

- Only P2WPKH (BIP-84, native SegWit) coins.
- PayJoin is BIP-78 (v1) only: no BIP-77 directory or OHTTP.
- CoinJoin follows the joinstr spec, but PSBTs are version 0 and the LSAG recovery phase is not
  implemented; rounds have only been run between deadhop wallets, not with joinstr's Python or
  Kotlin clients.
- The PayJoin and CoinJoin Compose setups have not been run end to end yet; both modes are
  tested in deadhop/wallet's regtest suite.
