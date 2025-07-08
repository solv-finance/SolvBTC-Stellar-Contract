use soroban_sdk::{contracttype, Address, Bytes, Env, Vec};

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
        target_amount: i128,
        nav: i128,
        request_hash: Bytes,
        timestamp: u64,
        signature: Bytes,
    ) -> i128;

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

    /// Set withdrawal currency by admin
    fn set_withdraw_currency_by_admin(env: Env, currency: Address);

    /// Get supported currencies list
    fn get_supported_currencies(env: Env) -> Vec<Address>;

    /// Check if currency is supported
    fn is_currency_supported(env: Env, currency: Address) -> bool;

    /// Get withdrawal currency
    fn get_withdraw_currency(env: Env) -> Option<Address>;
}

// ==================== System Management Functions ====================

/// System management trait
pub trait SystemManagement {
    /// Set withdrawal verifier by admin
    fn set_withdraw_verifier_by_admin(env: Env, verifier_address: Address);

    /// Set Oracle by admin
    fn set_oracle_by_admin(env: Env, oracle: Address);

    /// Set treasurer by admin
    fn set_treasurer_by_admin(env: Env, treasurer: Address);

    /// Set Minter Manager by admin
    fn set_minter_manager_by_admin(env: Env, minter_manager: Address);

    /// Set withdrawal fee ratio by admin
    fn set_withdraw_ratio_by_admin(env: Env, withdraw_ratio: i128);

    /// Set EIP712 domain parameters by admin
    fn set_eip712_domain_by_admin(
        env: Env,
        name: soroban_sdk::String,
        version: soroban_sdk::String,
    );
}

// ==================== Query Functions ====================

/// Query trait
pub trait VaultQuery {
    /// Get admin address
    fn admin(env: Env) -> Address;

    /// Get withdrawal verifier address
    fn get_withdraw_verifier(env: Env) -> Address;

    /// Get Oracle address
    fn get_oracle(env: Env) -> Address;

    /// Get treasurer address
    fn get_treasurer(env: Env) -> Address;

    /// Get Minter Manager address
    fn get_minter_manager(env: Env) -> Address;

    /// Get withdrawal fee ratio
    fn get_withdraw_ratio(env: Env) -> i128;

    /// Check if contract is initialized
    fn is_initialized(env: Env) -> bool;

    /// Get EIP712 domain name
    fn get_eip712_domain_name(env: Env) -> soroban_sdk::String;

    /// Get EIP712 domain version
    fn get_eip712_domain_version(env: Env) -> soroban_sdk::String;

    /// Get EIP712 chain ID
    fn get_eip712_chain_id(env: Env) -> soroban_sdk::Bytes;

    /// Get EIP712 domain separator
    fn get_eip712_domain_separator(env: Env) -> soroban_sdk::Bytes;
}

// ==================== Initialization Functions ====================

/// Initialization trait
pub trait VaultInitialization {
    /// Initialize contract
    fn initialize(
        env: Env,
        admin: Address,
        minter_manager: Address,
        token_contract: Address,
        oracle: Address,
        treasurer: Address,
        withdraw_verifier: Address,
        withdraw_ratio: i128,
        eip712_domain_name: soroban_sdk::String,
        eip712_domain_version: soroban_sdk::String,
    );
}

// ==================== Event Definitions ====================

/// Deposit event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositEvent {
    pub user: Address,
    pub currency: Address,
    pub amount: i128,
    pub token_contract: Address,
    pub minted_tokens: i128,
    pub nav: i128,
}

/// Withdrawal event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawEvent {
    pub from: Address,
    pub target_amount: i128,
    pub gross_amount: i128,
    pub fee_amount: i128,
    pub actual_amount: i128,
    pub burned_tokens: i128,
    pub nav: i128,
    pub request_hash: Bytes,
}

/// Currency added event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrencyAddedEvent {
    pub admin: Address,
    pub currency: Address,
}

/// Currency removed event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrencyRemovedEvent {
    pub admin: Address,
    pub currency: Address,
}
