# Makefile for hierarkey workspace

# Default target
.PHONY: all
all: clippy fmt test build

# ------------------------
# Basic Rust targets
# ------------------------

# Build all crates in the workspace
.PHONY: build
build:
	cargo build --workspace

fix:
	cargo fmt --all
	cargo clippy --fix --workspace --all-targets --all-features -- -D warnings

# Run tests for all crates in the workspace
.PHONY: test
test:
	cargo test --workspace

# Format all Rust code
.PHONY: fmt
fmt:
	cargo fmt --all

# Run clippy on the whole workspace
.PHONY: clippy
clippy:
	cargo clippy --workspace --all-targets --all-features  -- -D warnings

# Clean target
.PHONY: clean
clean:
	cargo clean

