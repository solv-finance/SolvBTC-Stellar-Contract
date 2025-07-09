# SolvBTC Stellar Contracts

这个项目包含了 SolvBTC 在 Stellar Soroban 平台上的智能合约实现。

## 项目结构

- `fungible-token/`: 可替代代币合约
- `minter-manager/`: 铸币管理合约
- `oracle/`: 价格预言机合约
- `vault/`: 金库合约
- `tests/`: 集成测试

## 开发环境设置

### 前置条件

- Rust 1.74.0 或更高版本
- Soroban CLI
- wasm32-unknown-unknown 目标

### 安装依赖

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup target add wasm32-unknown-unknown

# 安装 Soroban CLI
cargo install --locked soroban-cli
```

## 构建和测试

### 构建所有合约

```bash
make build
```

### 运行所有测试

```bash
make test
```

### 只运行集成测试

```bash
make integration-test
```

### 代码质量检查

```bash
make check
```

### 自动修复代码问题

```bash
make fix
```

## 部署

### 生成 TypeScript 绑定

```bash
make generate-js
```

## 许可证

[添加许可证信息]

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

