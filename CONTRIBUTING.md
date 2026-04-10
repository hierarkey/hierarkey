# Contributing to Hierarkey

Thank you for your interest in contributing! This document explains how to get
started, what we expect from contributions, and how the review process works.

## Contributor License Agreement

Before your pull request can be merged you must agree to the
[Contributor License Agreement](CLA.md). The CLA allows Noxlogic to
dual-license the project — distributing the community edition under AGPL-3.0
while offering a commercial edition — without requiring additional permission
from contributors.

The CLA bot will prompt you to sign on your first pull request. You only need
to do this once.

## Development Setup

### Prerequisites

- Rust stable toolchain (see `rust-version` in `Cargo.toml` for the minimum
  supported version — `rustup` is recommended)
- PostgreSQL 14+
- `cargo-deny` for dependency and license audits:
  ```sh
  cargo install cargo-deny
  ```
- `rustfmt` and `clippy` are bundled with the Rust toolchain

### Database

Create a local PostgreSQL database, then generate and edit the configuration file:

```sh
cargo build --release

./target/release/hierarkey generate-config --output hierarkey-config.toml
# edit hierarkey-config.toml and set your database URL
```

Apply migrations and bootstrap the server for local development:

```sh
./target/release/hierarkey update-migrations --config hierarkey-config.toml
./target/release/hierarkey bootstrap-master-key --config hierarkey-config.toml \
    --usage wrap_kek --provider passphrase --generate-passphrase
./target/release/hierarkey bootstrap-admin-account --config hierarkey-config.toml \
    --name admin
```

Start the server:

```sh
./target/release/hierarkey serve --config hierarkey-config.toml
```

## Building

```sh
cargo build
```

Release build:

```sh
cargo build --release
```

## Running Tests

Unit tests:

```sh
cargo test
```

Dependency, license, and advisory audit:

```sh
cargo deny check
```

## Use of AI Tools

AI tools (such as LLMs and code assistants) are used as part of the development
workflow on this project. See [docs/AI-usage.md](docs/AI-usage.md) for how we use
them and what we expect of that usage.

Contributors are welcome to use AI tools in their contributions, with the same
expectations: review what is generated, understand it, and take ownership of it.
Blindly submitted AI-generated code that hasn't been read or validated will not
be merged.

## Code Style

All code must pass `rustfmt` and `clippy` without warnings before it can be
merged. CI enforces both checks — submissions that fail either will not be merged.

Format your code:

```sh
cargo fmt
```

Lint your code:

```sh
cargo clippy -- -D warnings
```

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, keeping commits focused and atomic.
3. Ensure `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` all pass.
4. Open a pull request against `main` with a clear description of what changed
   and why.
5. The CLA bot will ask you to sign the CLA if you haven't already.
6. A maintainer will review your PR. Please respond to review comments promptly.

## Reporting Bugs

Open a [GitHub issue](https://github.com/hierarkey/hierarkey/issues) and include:

- A clear description of the bug and expected behaviour
- Steps to reproduce
- Hierarkey version (`hierarkey --version` / `hkey --version`)
- Relevant logs or configuration (redact any secrets)

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Scope

This repository contains the **community edition** of Hierarkey. Features that
are part of the commercial edition are maintained separately and are out of
scope for contributions here.
