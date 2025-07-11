# SolvBTC Stellar Contracts

This project contains the implementation of SolvBTC smart contracts on the Stellar Soroban platform.

## Project Structure

- `fungible-token/`: Fungible token contract
- `minter-manager/`: Minter management contract
- `oracle/`: Price oracle contract
- `vault/`: Vault contract
- `tests/`: Integration tests

## Development Environment Setup

### Prerequisites

- Rust 1.74.0 or higher
- Soroban CLI
- wasm32-unknown-unknown target

### Installing Dependencies

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup target add wasm32-unknown-unknown

# Install Soroban CLI
cargo install --locked soroban-cli
```

## Building and Testing

### Build All Contracts

```bash
make build
```

### Run All Tests

```bash
make test
```

### Run Integration Tests Only

```bash
make integration-test
```

### Code Quality Check

```bash
make check
```

### Automatically Fix Code Issues

```bash
make fix
```

## Deployment

### Generate TypeScript Bindings

```bash
make generate-js
```

## Project Structure

The project is organized as a Cargo workspace with the following components:

- **fungible-token**: Implementation of a fungible token contract compatible with Stellar standards
- **vault**: Main vault contract for managing deposits and withdrawals
- **oracle**: NAV (Net Asset Value) oracle contract for price feeds
- **minter-manager**: Contract for managing token minting permissions
- **integration-tests**: End-to-end integration tests for the contracts
- **key-test**: Testing utilities for cryptographic operations

## Prerequisites

- Rust and Cargo (latest stable version)
- [Soroban CLI](https://soroban.stellar.org/docs/getting-started/setup) with `opt` feature
- Wasm target: `rustup target add wasm32-unknown-unknown`

## Building the Project

To build all contracts:

```bash
make build
```

This will:
1. Compile all contracts
2. Generate WASM files for each contract
3. Optimize the WASM files using Soroban's optimizer
4. Output the optimized WASM files to `target/wasm32-unknown-unknown/optimized/`

## Running Tests

To run all tests:

```bash
make test
```

This will run both unit tests and integration tests for all contracts.

## Development Commands

- `make fmt`: Format the code using rustfmt
- `make clean`: Clean build artifacts
- `make generate-js`: Generate TypeScript bindings for the contracts

## Contract Details

### Fungible Token

A standard-compliant fungible token with additional features:
- Minting and burning capabilities
- Blacklist functionality
- Pausable transfers
- Admin controls

### Vault

The main vault contract that:
- Manages deposits of assets
- Processes withdrawals with cryptographic verification
- Interacts with the oracle for NAV updates

### Oracle

Provides NAV (Net Asset Value) data:
- Managed by authorized administrators
- Enforces limits on NAV changes
- Supports configurable precision

### Minter Manager

Manages token minting permissions:
- Controls which addresses can mint tokens
- Sets minting limits
- Provides admin functions for managing minters

