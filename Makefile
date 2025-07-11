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
	cargo rustc --manifest-path=minter-manager/Cargo.toml --crate-type=cdylib --target=wasm32-unknown-unknown --release
	mkdir -p target/wasm32-unknown-unknown/optimized
	soroban contract optimize \
		--wasm target/wasm32-unknown-unknown/release/fungible_token.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/fungible_token.wasm
	soroban contract optimize \
		--wasm target/wasm32-unknown-unknown/release/solvbtc_vault.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/solvbtc_vault.wasm
	soroban contract optimize \
		--wasm target/wasm32-unknown-unknown/release/solvbtc_oracle.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/solvbtc_oracle.wasm
	soroban contract optimize \
		--wasm target/wasm32-unknown-unknown/release/minter_manager.wasm \
		--wasm-out target/wasm32-unknown-unknown/optimized/minter_manager.wasm
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
	soroban contract bindings typescript --overwrite \
		--contract-id CAPQXPPAIUDIJRRDXLUAIY4QRG5QCJN2B5SFGQOGB6GPBSXKK6GX2ZKQ \
		--wasm ./target/wasm32-unknown-unknown/optimized/fungible_token.wasm --output-dir ./js/js-fungible-token/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone
	soroban contract bindings typescript --overwrite \
		--contract-id CB22PCIBZJQMEO7KLV4WUWDG7N6BRQ6QN3ALYGOUYO3ZPLVC2CS5V46K \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_vault.wasm --output-dir ./js/js-vault/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone
	soroban contract bindings typescript --overwrite \
		--contract-id CBMKIQH4PJ6LN7DVG2G7TJLGPJUDOWGIH2UY5ULOGDAHKBSWMOXC3FMM \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_oracle.wasm --output-dir ./js/js-oracle/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone
	soroban contract bindings typescript --overwrite \
		--contract-id CDRQZFAHFFYYVHRAQE7M4LNR2UZUZNVOEA4T2QQP4MYOXEN5GEIIXIWI \
		--wasm ./target/wasm32-unknown-unknown/optimized/minter_manager.wasm --output-dir ./js/js-minter-manager/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone

.PHONY: default test build integration-test check fix doc fmt clean generate-js 