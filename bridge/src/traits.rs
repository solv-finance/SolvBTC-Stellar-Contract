use soroban_sdk::{contracttype, contracterror, Address, Bytes, BytesN, Env};

// ==================== Bridge Core Traits ====================

/// Bridge Functionality Trait
pub trait BridgeOperations {
    /// Mint SolvBTC
    fn mint(
        env: Env,
        from: Address,
        signature: BytesN<65>,
        btc_tx_hash: Bytes,
        btc_amount: i128,
        btc_amount_str: Bytes,
        nav: i128,
        nav_str: Bytes,
        token_address: Address,
    );

    /// Redeem SolvBTC
    fn redeem(
        env: Env,
        from: Address,
        token_address: Address,
        amount: i128,
        receiver: Bytes,
    );
}

/// Bridge Admin Trait
pub trait BridgeAdmin {
    /// Set the signer's per-mint cap (maximum mint amount allowed per `mint` call).
    /// This cap is a single-transaction upper bound and is not decremented by the contract.
    fn set_signer_cap(env: Env, signer: BytesN<65>, cap: i128);

    /// Set the Oracle address (validated against token/BTC decimals)
    fn set_oracle(env: Env, oracle: Address);
}

/// Read-only query functions
pub trait BridgeQuery {
    /// Get the configured per-mint cap for a given recovered public key
    fn get_signer_cap(env: Env, signer: BytesN<65>) -> i128;

    /// Get the configured token contract address
    fn get_token(env: Env) -> Address;

    /// Get the configured oracle contract address
    fn get_oracle(env: Env) -> Address;

}

// ==================== Events ====================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintEvent {
    pub btc_tx_hash: Bytes,
    pub token_address: Address,
    pub from: Address,
    pub to: Address,
    pub nav: i128,
    pub btc_amount: i128,
    pub mint_amount: i128,
    pub op_return_hash: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedeemEvent {
    pub token: Address,
    pub user: Address,
    pub btc_receiver: Bytes,
    pub shares: i128,
    pub btc_amount: i128,
    pub nav: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetSignerCapEvent {
    pub admin: Address,
    pub signer: BytesN<65>,
    /// Per-mint cap value
    pub cap: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetOracleEvent {
    pub admin: Address,
    pub oracle: Address,
}

// ==================== Errors ====================

#[contracterror]
#[derive(Clone, Debug, Copy, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BridgeError {
    InvalidAmount = 401,
    InvalidNav = 402,
    Unauthorized = 403,
    TokenNotSupported = 404,
    TxAlreadyUsed = 405,
    InvalidSignature = 406,
    SignerCapExceeded = 407,
    AllowPushDisabled = 408,
    InvalidSignerKey = 409,
    NavOutOfRange = 410,
    InvalidDecimals = 411,
    InvalidAddress = 412,
    InvalidData = 413,
}
