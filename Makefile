default: build

test: build
	cargo test --all --tests

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

fmt:
	cargo fmt --all

clean:
	cargo clean

generate-js:
	soroban contract bindings typescript --overwrite \
		--contract-id CBWH54OKUK6U2J2A4J2REJEYB625NEFCHISWXLOPR2D2D6FTN63TJTWN \
		--wasm ./target/wasm32-unknown-unknown/optimized/fungible_token.wasm --output-dir ./js/js-fungible-token/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone
	soroban contract bindings typescript --overwrite \
		--contract-id CBWH54OKUK6U2J2A4J2REJEYB625NEFCHISWXLOPR2D2D6FTN63TJTWN \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_vault.wasm --output-dir ./js/js-vault/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone
	soroban contract bindings typescript --overwrite \
		--contract-id CBWH54OKUK6U2J2A4J2REJEYB625NEFCHISWXLOPR2D2D6FTN63TJTWN \
		--wasm ./target/wasm32-unknown-unknown/optimized/solvbtc_oracle.wasm --output-dir ./js/js-oracle/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone
	soroban contract bindings typescript --overwrite \
		--contract-id CBWH54OKUK6U2J2A4J2REJEYB625NEFCHISWXLOPR2D2D6FTN63TJTWN \
		--wasm ./target/wasm32-unknown-unknown/optimized/minter_manager.wasm --output-dir ./js/js-minter-manager/ \
		--rpc-url http://localhost:8000 --network-passphrase "Standalone Network ; February 2017" --network Standalone 