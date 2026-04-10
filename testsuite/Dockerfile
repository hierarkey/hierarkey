FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

# Create a dummy src/main.rs so `cargo build` can fetch deps
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
RUN rm -rf src


FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y \
    postgresql-client \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry

WORKDIR /test-suite

COPY test-suite/pyproject.toml test-suite/poetry.lock* ./
RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

RUN mkdir -p /opt/hierarkey

EXPOSE 8080