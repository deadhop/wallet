# deadhop-wallet

The sweeping wallet. It is a separate binary and container from the payment service.

- **It holds the funds** of the wallet the payment service watches.
- **It moves them out** once the confirmed balance reaches a threshold, to a fresh address of
  another wallet, in one of three ways:

| Mode | What happens |
|---|---|
| `send` (default) | One transaction pays every confirmed coin to the next unused address of `DEADHOP_WALLET_DESTINATION`. |
| `payjoin` | A [BIP-78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) PayJoin with a receiver named by a `bitcoin:` URI that has a `pj=` endpoint. The receiver adds a coin of its own, so the transaction does not show which inputs are whose. |
| `coinjoin` | A [joinstr](https://docs.joinstr.xyz/protocol/) round over Nostr. The confirmed coins are first consolidated into one premix coin. That coin joins a pool of equal-amount peers, and the mixed output goes to the next destination address. |

## How it fits

- **The phrase:** the offline `wallet` service (`deadhop wallet serve`) still generates and keeps the
  recovery phrase. This process reads the phrase, read-only. It never creates one, so a
  missing file can never turn into a new, empty wallet.
- **Startup check:** it refuses to start if the phrase does not belong to the account key the
  payment service watches (`DEADHOP_XPUB_FILE`).
- **Finding the coins:** the payment service gives every invoice its own address, and most
  invoices are never paid, so a gap-limit scan alone would miss funds. The payment service
  therefore writes its next unused address index to `DEADHOP_INDEX_FILE` after every poll. The
  wallet scans every address below it, plus `DEADHOP_WALLET_GAP` beyond the last used one.
- **Before every signature,** whoever built the transaction (this wallet, a PayJoin receiver or
  CoinJoin peers), the wallet checks three things:
  - it spends only its own coins, and their values are described correctly;
  - at least the expected amount reaches the approved scripts: the destination, or for a
    premix its own change;
  - it loses no more than the allowed cost: the fee cap for a send or a premix, the Original's
    fee for a PayJoin, and joinstr's 15,000 sat for a CoinJoin.
- **Destination and limits:** the destination, mode, threshold and fee cap are read from the
  environment only. Nothing that decides where money goes can be changed remotely. The sweep
  policy in the dashboard is a separate, stored setting and does not drive this process.
- **State:** `sweeper.json` in `DEADHOP_WALLET_STATE_DIR` records the next destination and
  change index, every PayJoin URI already paid (each is paid once), and the last 100 sweeps.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DEADHOP_NETWORK` | `bitcoin` | `bitcoin`, `testnet`, `signet` or `regtest` |
| `DEADHOP_DATA_DIR` | `data` | Holds `wallet.mnemonic` (only read) |
| `DEADHOP_XPUB_FILE` | `<data>/account.xpub` | The account key the payment service watches |
| `DEADHOP_XPUB` | unset | When set, the keys are elsewhere: the process says so and idles |
| `DEADHOP_INDEX_FILE` | unset | The payment service's next unused address index |
| `DEADHOP_WALLET_STATE_DIR` | the data directory | Where `sweeper.json` is kept (must be writable) |
| `DEADHOP_ELECTRUM`, `DEADHOP_ELECTRUM_CERT_SHA256` | none | As for the payment service. Required to sweep |
| `DEADHOP_WALLET_MODE` | `send` | `send`, `payjoin` or `coinjoin` |
| `DEADHOP_WALLET_DESTINATION` | unset | Account key (`xpub`/`zpub`, `tpub`/`vpub`) of the wallet to move funds to. Unset: hold, sweep nothing, connect nowhere |
| `DEADHOP_WALLET_THRESHOLD_SAT` | `1000000` | Confirmed balance that triggers a sweep (at least 10,000) |
| `DEADHOP_WALLET_MAX_FEE_RATE` | `20` | Highest fee rate in sat/vB. Above it, the sweep waits |
| `DEADHOP_WALLET_FEE_TARGET_BLOCKS` | `6` | Confirmation target asked of the server's fee estimate |
| `DEADHOP_WALLET_MIN_CONFIRMATIONS` | `1` | Confirmations a coin needs before it counts |
| `DEADHOP_WALLET_POLL_SECS` | `300` | Time between polls |
| `DEADHOP_WALLET_GAP` | `50` | Unused addresses scanned past the last used one |
| `DEADHOP_WALLET_PROXY` | unset | `socks5://…` (e.g. Tor) for PayJoin requests and the CoinJoin relay. Needed for `.onion` endpoints |
| `DEADHOP_WALLET_PAYJOIN_URI_FILE` | unset | `payjoin` mode: a file with the receiver's `bitcoin:…?pj=…` URI, without an amount. Write a fresh one for every sweep |
| `DEADHOP_WALLET_PAYJOIN_CERT_SHA256` | unset | Pin the receiver's certificate (self-hosted receivers) |
| `DEADHOP_WALLET_COINJOIN_RELAY` | unset | `coinjoin` mode: the one relay pools use |
| `DEADHOP_WALLET_COINJOIN_DENOMINATION_SAT` | `1000000` | Amount each peer mixes. The threshold must be at least this plus 500 |
| `DEADHOP_WALLET_COINJOIN_PEERS` | `5` | Peers per round, this wallet included |
| `DEADHOP_WALLET_COINJOIN_TIMEOUT_SECS` | `1800` | How long a round may take before it is abandoned |

Commands: `deadhop-wallet run` (the default: poll until stopped), `deadhop-wallet once` (one
poll) and `deadhop-wallet status` (recent sweeps).

## What happens when something fails

- **Fees above the cap, no fresh PayJoin URI, a CoinJoin round that does not fill:** the
  balance stays where it is, and the next poll tries again.
- **PayJoin receiver unreachable, answering with an error, or sending a proposal that fails a
  check:** the signed Original is broadcast instead. It is an ordinary payment to the
  receiver's address, and BIP-78 lets the receiver broadcast it too. The URI counts as used
  either way.
- **CoinJoin:** a signature is `ALL|ANYONECANPAY` over every output, so whatever set of inputs
  ends up combined, this wallet's output gets its amount, or the transaction is invalid. An
  abandoned round spends nothing.

## Limits of this version

- **joinstr compatibility:** the message flow and field names follow the joinstr spec, but
  PSBTs are version 0 (the bitcoin library has no version 2), and the LSAG recovery phase is
  not implemented.
- **Untested against other implementations:** interoperability with joinstr's Python and
  Kotlin clients has not been tested. Rounds have only been run between deadhop wallets.
- **PayJoin version:** PayJoin is BIP-78 (v1) only, with no BIP-77 directory or OHTTP.
- **Script type:** only P2WPKH (BIP-84) coins.

## Tests

The hermetic tests run anywhere. The regtest tests broadcast real transactions on the dev
stack (`just up`):
- a simple send;
- a PayJoin with a BIP-78 receiver built on the `payjoin` crate's receiver;
- the PayJoin fallback;
- a three-wallet CoinJoin over the private relay.

```sh
cd wallet && cargo test                                   # hermetic
DEADHOP_WALLET_REGTEST=1 cargo test --test regtest        # needs `just up`
DEADHOP_WALLET_REGTEST=1 cargo llvm-cov --all-targets     # coverage
```
