default: build

# Run all tests
test: build
	cargo test --all --tests

# Build all contracts
build:
	cargo build
	cargo rustc --manifest-path=fungible-token/Cargo.toml --crate-type=cdylib --target=wasm32-unknown-unknown --release
	cargo rustc --manifest-path=vault/Cargo.toml --crate-type=cdylib --target=wasm32-unknown-unknown --release
	cargo rustc --manifest-path=oracle/Cargo.toml --crate-type=cdylib --target=wasm32-unknown-unknown --release
	cargo rustc --manifest-path=bridge/Cargo.toml --crate-type=cdylib --target=wasm32-unknown-unknown --release
	mkdir -p target/wasm32-unknown-unknown/optimized
	stellar contract optimize \
		--wasm target/wasm32-unknown-unknown/release/fungible_token.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/fungible_token.wasm
	stellar contract optimize \
		--wasm target/wasm32-unknown-unknown/release/solvbtc_vault.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/solvbtc_vault.wasm
	stellar contract optimize \
		--wasm target/wasm32-unknown-unknown/release/solvbtc_oracle.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/solvbtc_oracle.wasm
	stellar contract optimize \
		--wasm target/wasm32-unknown-unknown/release/solvbtc_bridge.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/solvbtc_bridge.wasm
	cd target/wasm32-unknown-unknown/optimized/ && \
		for i in *.wasm ; do \
			ls -l "$$i"; \
		done

# Run integration tests only
integration-test: build
	cargo test -p tests

# Check code format and issues
check:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

# Fix code format and simple issues
fix:
	cargo fmt --all
	cargo clippy --all-targets --fix -- -D warnings

# Generate documentation
doc:
	cargo doc --no-deps --document-private-items --open

fmt:
	cargo fmt --all

clean:
	cargo clean

generate-js:
	stellar contract bindings typescript --overwrite \
		--wasm ./target/wasm32-unknown-unknown/optimized/fungible_token.wasm \
		--output-dir ./js-bindings/fungible-token/ \
		--network testnet
	stellar contract bindings typescript --overwrite \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_vault.wasm \
		--output-dir ./js-bindings/vault/ \
		--network testnet
	stellar contract bindings typescript --overwrite \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_oracle.wasm \
		--output-dir ./js-bindings/oracle/ \
		--network testnet
	stellar contract bindings typescript --overwrite \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_bridge.wasm \
		--output-dir ./js-bindings/bridge/ \
		--network testnet

.PHONY: default test build integration-test check fix doc fmt clean generate-js 