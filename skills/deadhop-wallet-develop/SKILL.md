---
name: deadhop-wallet-develop
description: "Contribute to deadhop wallet (deadhop-wallet, the Rust sweeper that spends from deadhop's generated wallet): run the gate (just check), run the regtest sweeps with coverage (just regtest, which needs deadhop/stack's regtest stack), and move the shared crates from deadhop/server (just update-server-crates). Use it whenever you change code, tests, Cargo.toml or Cargo.lock in the deadhop/wallet repository, a wallet CI run fails, someone wants to run the regtest send, PayJoin or CoinJoin tests, or asks how to build, test or contribute to the sweeper."
license: MIT
metadata:
  repository: https://github.com/deadhop/wallet
---

# Develop deadhop wallet

One Rust crate with one binary, `deadhop-wallet` (`src/main.rs` is one call into the library).
It signs real Bitcoin transactions, so every change is reviewed with that in mind.
Requirements: Rust 1.99, [`just`](https://github.com/casey/just), and for `just regtest`
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) and Docker.

## The gate

```sh
just check
```

It runs `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and
`cargo test --locked` (the hermetic tests; the regtest tests skip themselves). CI runs the same
on every pull request; run it before you push. `--locked` means `Cargo.lock` must match
`Cargo.toml`: commit it with any dependency change.

## The regtest sweeps

```sh
just regtest     # DEADHOP_WALLET_REGTEST=1 cargo llvm-cov --all-targets --fail-under-functions 100
```

`tests/regtest.rs` broadcasts real transactions on a local regtest chain: a simple send, a
PayJoin against a BIP-78 receiver built on the `payjoin` crate's receiver, the PayJoin fallback,
and a three-wallet CoinJoin over the stack's relay. Coverage must reach 100% of functions.

They need the regtest stack from https://github.com/deadhop/stack: bitcoind, Fulcrum on
`127.0.0.1:50001` and a relay on `ws://127.0.0.1:7777`, everything on loopback.

```sh
git clone https://github.com/deadhop/stack && cd stack
just clone        # clones server, js, lnaddr, wallet and relay next to the stack's files
just up           # starts the regtest stack and its two wallets
cd wallet && just regtest
```

Without `DEADHOP_WALLET_REGTEST=1` they print `skipped` and pass, so a green `just check` says
nothing about them: run `just regtest` for any change to signing, transaction building,
scanning, PayJoin or CoinJoin. `just down` in the stack stops it and deletes the chain data.

## Rules the code keeps

Keep these properties; tests check them, and a change that weakens one needs a very good
reason in the pull request:

- **Never creates a recovery phrase.** It only reads `wallet.mnemonic`, so a missing file can
  never become a new, empty wallet. It refuses to start if the phrase does not match the account
  key the service watches (`DEADHOP_XPUB_FILE`).
- **Destination, mode, threshold and fee cap come from the environment only.** Nothing remote
  may change where money goes.
- **Checks before every signature**, whoever built the transaction: it spends only its own coins
  with correctly described values; at least the expected amount reaches the approved scripts;
  it loses no more than the allowed cost (the fee cap, the PayJoin Original's fee, or joinstr's
  15,000 sat).
- **With nothing to sweep to, it reads no key and connects nowhere.**
- Settings are `DEADHOP_WALLET_*` (plus the service's `DEADHOP_NETWORK`, `DEADHOP_DATA_DIR`,
  `DEADHOP_XPUB`, `DEADHOP_XPUB_FILE`, `DEADHOP_INDEX_FILE`, `DEADHOP_ELECTRUM`), read in
  `src/config.rs`, numbers with their bounds. A new one also goes into deadhop/stack's `compose.yaml`
  (`sweeper` service) through a pull request there.

## Shared crates from deadhop/server

`deadhop-common`, `deadhop-electrum`, `deadhop-net` and `deadhop-tlspin` come from
https://github.com/deadhop/server by git (`branch = "main"`), pinned by `Cargo.lock`.

```sh
just update-server-crates   # cargo update -p deadhop-common -p deadhop-electrum -p deadhop-net -p deadhop-tlspin
just check
```

- A change those crates need goes to deadhop/server first; once merged, update here, adapt,
  and open the wallet pull request.
- Never commit a `Cargo.lock` whose `deadhop-*` entries lack a
  `source = "git+https://github.com/deadhop/server…"` line (for example after a local path
  override): CI's `--locked` build fails on it.
- The repository must build from its own clone: no path dependencies that reach outside it.

## Docs and pull requests

- The user docs are in https://github.com/deadhop/site under `docs/wallet/`. A change to a
  setting, command, log line or limit needs a matching pull request there.
- Open issues and pull requests in https://github.com/deadhop/wallet.
- Never commit a real recovery phrase, private key or `.env`. The tests use their own fixed test
  phrase and keys.
