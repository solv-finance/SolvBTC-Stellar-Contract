use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, String, Vec};

// ==================== Deposit and Withdrawal Functions ====================

/// EIP712 signature data structure: withdrawal request
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequest {
    pub user: Address,
    pub target_amount: i128,
    pub nav: i128,
    pub request_hash: Bytes,
    pub timestamp: u64,
    pub signature: Bytes,
}

/// Deposit and withdrawal functionality trait
pub trait VaultOperations {
    /// User deposit
    ///
    /// # Parameters
    /// - `from`: User address (caller)
    /// - `currency`: Deposit currency address
    /// - `amount`: Deposit amount
    ///
    /// # Returns
    /// Returns the amount of tokens minted
    fn deposit(env: Env, from: Address, currency: Address, amount: i128) -> i128;

    /// User withdrawal
    ///
    /// # Parameters
    /// - `from`: User address (caller)
    /// - `target_amount`: Target withdrawal amount
    /// - `nav`: NAV value
    /// - `request_hash`: Request hash
    /// - `signature`: Signature
    ///
    /// # Returns
    /// Returns the actual withdrawal amount
    fn withdraw(
        env: Env,
        from: Address,
        shares: i128,
        nav: i128,
        request_hash: Bytes,
        signature: BytesN<64>,
        signature_type: u32,
        recovery_id: u32,
    ) -> i128;

    /// Withdraw request
    fn withdraw_request(env: Env, from: Address, shares: i128, request_hash: Bytes);

    /// Treasurer deposit (prepare liquidity for withdrawals)
    fn treasurer_deposit(env: Env, amount: i128);
}

// ==================== Currency Management Functions ====================

/// Currency management trait
pub trait CurrencyManagement {
    /// Add currency by admin
    fn add_currency_by_admin(env: Env, currency: Address);

    /// Remove currency by admin
    fn remove_currency_by_admin(env: Env, currency: Address);

    /// Get supported currencies list
    fn get_supported_currencies(env: Env) -> Vec<Address>;

    /// Check if currency is supported
    fn is_currency_supported(env: Env, currency: Address) -> bool;

    /// Get withdrawal currency
    fn get_withdraw_currency(env: Env) -> Option<Address>;

    /// Get shares (minted) token contract address
    fn get_shares_token(env: Env) -> Address;
}

// ==================== System Management Functions ====================

/// System management trait
pub trait SystemManagement {
    /// Set withdrawal verifier by admin for specific signature type
    /// - signature_type: 0 = Ed25519 (32 bytes), 1 = Secp256k1 (65 bytes uncompressed)
    /// - verifier_public_key: Public key bytes (size depends on signature type)
    fn set_withdraw_verifier_by_admin(env: Env, signature_type: u32, verifier_public_key: Bytes);

    /// Set Oracle by admin
    fn set_oracle_by_admin(env: Env, oracle: Address);

    /// Set treasurer by admin
    fn set_treasurer_by_admin(env: Env, treasurer: Address);

    /// Set withdrawal fee ratio by admin
    fn set_withdraw_fee_ratio_by_admin(env: Env, withdraw_fee_ratio: i128);

    /// Set deposit fee ratio by admin
    fn set_deposit_fee_ratio_by_admin(env: Env, deposit_fee_ratio: i128);

    /// Set withdraw fee receiver by admin
    fn set_withdraw_fee_recv_by_admin(env: Env, withdraw_fee_receiver: Address);
}

// ==================== Query Functions ====================
#[contractclient(name = "VaultClient")]
/// Query trait
pub trait VaultQuery {
    /// Get admin address
    fn get_admin(env: Env) -> Address;

    /// Get withdrawal verifier by signature type
    /// Returns the public key bytes for the specified signature type, or None if not set
    fn get_withdraw_verifier(env: Env, signature_type: u32) -> Option<Bytes>;

    /// Get Oracle address
    fn get_oracle(env: Env) -> Address;

    /// Get treasurer address
    fn get_treasurer(env: Env) -> Address;

    /// Get withdrawal fee ratio
    fn get_withdraw_fee_ratio(env: Env) -> i128;

    /// Get deposit fee ratio
    fn get_deposit_fee_ratio(env: Env) -> i128;

    /// Get withdrawal fee receiver
    fn get_withdraw_fee_receiver(env: Env) -> Address;

    /// Get EIP712 domain name
    fn get_eip712_domain_name(env: Env) -> String;

    /// Get EIP712 domain version
    fn get_eip712_domain_version(env: Env) -> String;

    /// Get EIP712 chain ID
    fn get_eip712_chain_id(env: Env) -> Bytes;

    /// Get EIP712 domain separator
    fn get_eip712_domain_separator(env: Env) -> Bytes;
}

// ==================== Event Definitions ====================

/// Deposit event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositEvent {
    pub amount: i128,
    pub minted_tokens: i128,
    pub nav: i128,
}

/// Withdrawal event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawEvent {
    pub amount: i128,
    pub fee: i128,
    pub request_hash: Bytes,
}

/// Currency added event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetAllowedCurrencyEvent {
    pub allowed: bool,
}

/// Currency removed event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrencyRemovedEvent {
    pub admin: Address,
}

/// Withdraw request event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequestEvent {
    pub token_contract: Address,
    pub shares: i128,
    pub request_hash: Bytes,
    pub nav: i128,
    pub amount: i128,
}

/// Treasurer deposit event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasurerDepositEvent {
    pub amount: i128,
}
