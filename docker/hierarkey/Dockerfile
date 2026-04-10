FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first to cache dependency compilation
COPY Cargo.toml Cargo.lock ./
COPY hierarkey-core/Cargo.toml ./hierarkey-core/
COPY hierarkey-server/Cargo.toml ./hierarkey-server/
COPY hierarkey-cli/Cargo.toml ./hierarkey-cli/

# Stub source files so cargo can resolve and cache all dependencies
RUN mkdir -p hierarkey-core/src \
             hierarkey-server/src/bin \
             hierarkey-cli/src/bin && \
    echo "pub fn stub() {}" > hierarkey-core/src/lib.rs && \
    echo "pub fn stub() {}" > hierarkey-server/src/lib.rs && \
    echo "pub fn stub() {}" > hierarkey-cli/src/lib.rs && \
    echo "fn main() {}" > hierarkey-server/src/bin/main.rs && \
    echo "fn main() {}" > hierarkey-cli/src/bin/main.rs && \
    cargo build --release 2>/dev/null || true

# Copy full source and rebuild (only changed crates recompile)
COPY . .
RUN touch hierarkey-core/src/lib.rs \
          hierarkey-server/src/lib.rs \
          hierarkey-server/src/bin/main.rs \
          hierarkey-cli/src/lib.rs \
          hierarkey-cli/src/bin/main.rs && \
    cargo build --release --bin hierarkey --bin hkey

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/hierarkey /usr/local/bin/hierarkey
COPY --from=builder /build/target/release/hkey      /usr/local/bin/hkey
COPY docker/hierarkey/entrypoint.sh                 /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    mkdir -p /data/master-keys

VOLUME /data
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
