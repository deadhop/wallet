# deadhop-wallet, the sweeping wallet. Build context: this repository's root.
# Cargo fetches the shared crates from deadhop/server at the commit Cargo.lock pins.
FROM rust:1.99-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin deadhop-wallet \
 && strip target/release/deadhop-wallet

FROM debian:trixie-slim
# Same user id as the offline wallet service, so it can read the recovery
# phrase that service wrote (owner-only) from a read-only mount.
RUN useradd --system --uid 10001 --home-dir /state --shell /usr/sbin/nologin deadhop \
 && install -d -o deadhop -g deadhop -m 0700 /state \
 && install -d -o deadhop -g deadhop -m 0700 /wallet \
 && install -d -o deadhop -g deadhop -m 0755 /wallet-public \
 && install -d -o deadhop -g deadhop -m 0755 /wallet-scan
COPY --from=build /src/target/release/deadhop-wallet /usr/local/bin/deadhop-wallet
USER deadhop
ENV DEADHOP_DATA_DIR=/wallet DEADHOP_WALLET_STATE_DIR=/state
VOLUME ["/state"]
ENTRYPOINT ["/usr/local/bin/deadhop-wallet"]
