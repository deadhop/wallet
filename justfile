# rustfmt, clippy (warnings are errors) and the hermetic tests
check:
    cargo fmt --check
    cargo clippy --all-targets --locked -- -D warnings
    cargo test --locked

# The regtest sweeps (simple send, PayJoin, CoinJoin), with coverage. Needs the
# regtest stack from https://github.com/deadhop/stack (`just clone`, then `just up` there).
regtest:
    DEADHOP_WALLET_REGTEST=1 cargo llvm-cov --all-targets --fail-under-functions 100

# Move the shared crates to the newest commit of deadhop/server's main
update-server-crates:
    cargo update -p deadhop-common -p deadhop-electrum -p deadhop-net -p deadhop-tlspin
