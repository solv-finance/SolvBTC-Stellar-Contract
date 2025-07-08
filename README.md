# SolvBTC Stellar Contracts

This repository contains the smart contracts for the SolvBTC platform built on Stellar Soroban.

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

