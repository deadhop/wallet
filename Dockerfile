# deadhop-wallet, the sweeping wallet. Build context: the repository root
# (it builds against the payment service's library in server/), with
# wallet/Dockerfile.dockerignore keeping everything else out.
FROM rust:1.99-slim-trixie AS build
WORKDIR /src
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY server/src ./server/src
COPY wallet/Cargo.toml wallet/Cargo.lock ./wallet/
COPY wallet/src ./wallet/src
RUN cd wallet && cargo build --release --locked --bin deadhop-wallet \
 && strip target/release/deadhop-wallet

FROM debian:trixie-slim
# Same user id as the offline wallet service, so it can read the recovery
# phrase that service wrote (owner-only) from a read-only mount.
RUN useradd --system --uid 10001 --home-dir /state --shell /usr/sbin/nologin deadhop \
 && install -d -o deadhop -g deadhop -m 0700 /state \
 && install -d -o deadhop -g deadhop -m 0700 /wallet \
 && install -d -o deadhop -g deadhop -m 0755 /wallet-public \
 && install -d -o deadhop -g deadhop -m 0755 /wallet-scan
COPY --from=build /src/wallet/target/release/deadhop-wallet /usr/local/bin/deadhop-wallet
USER deadhop
ENV DEADHOP_DATA_DIR=/wallet DEADHOP_WALLET_STATE_DIR=/state
VOLUME ["/state"]
ENTRYPOINT ["/usr/local/bin/deadhop-wallet"]
