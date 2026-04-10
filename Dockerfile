FROM rust:slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY hierarkey-core/ hierarkey-core/
COPY hierarkey-server/ hierarkey-server/
COPY hierarkey-cli/ hierarkey-cli/
COPY hierarkey-config.toml.example ./

RUN cargo build --release --bin hierarkey --bin hkey


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/hierarkey /usr/local/bin/hierarkey
COPY --from=builder /build/target/release/hkey /usr/local/bin/hkey

CMD ["/usr/local/bin/hierarkey"]
