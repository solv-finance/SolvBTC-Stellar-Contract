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
    );

    /// Redeem SolvBTC
    fn redeem(
        env: Env,
        from: Address,
        amount: i128,
        receiver: Bytes,
    );
}

/// Bridge Admin Trait
pub trait BridgeAdmin {
    /// Set the signer's mint policy (per-mint cap + window cap, in BTC sats).
    fn set_signer_policy(env: Env, signer: BytesN<65>, cap: i128, window_cap: i128, duration: u64);

    /// Set the Oracle address (validated against token/BTC decimals)
    fn set_oracle(env: Env, oracle: Address);
}

/// Read-only query functions
pub trait BridgeQuery {
    /// Get the configured signer mint policy (cap, window_cap, duration).
    fn get_signer_policy(env: Env, signer: BytesN<65>) -> (i128, i128, u64);

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
pub struct SetSignerPolicyEvent {
    pub admin: Address,
    pub signer: BytesN<65>,
    pub cap: i128,
    pub window_cap: i128,
    pub duration: u64,
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
    InvalidData = 408,
    InvalidSignerKey = 409,
    NavOutOfRange = 410,
    InvalidDecimals = 411,
    InvalidAddress = 412,
    SignerWindowCapExceeded = 413,
    InvalidSignerPolicy = 414,
}
