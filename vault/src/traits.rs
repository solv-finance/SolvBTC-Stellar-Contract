use soroban_sdk::{contractclient, contracttype, Address, Bytes, Env, String, Vec};

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
    fn set_withdraw_fee_ratio_by_admin(env: Env, withdraw_fee_ratio: i128);

    /// Set withdraw fee receiver by admin
    fn set_withdraw_fee_recv_by_admin(env: Env, withdraw_fee_receiver: Address);

    /// Set EIP712 domain parameters by admin
    fn set_eip712_domain_by_admin(env: Env, name: String, version: String);
}

// ==================== Query Functions ====================
#[contractclient(name = "VaultClient")]
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
    fn get_withdraw_fee_ratio(env: Env) -> i128;

    /// Get withdrawal fee receiver
    fn get_withdraw_fee_receiver(env: Env) -> Address;

    /// Check if contract is initialized
    fn is_initialized(env: Env) -> bool;

    /// Get EIP712 domain name
    fn get_eip712_domain_name(env: Env) -> String;

    /// Get EIP712 domain version
    fn get_eip712_domain_version(env: Env) -> String;

    /// Get EIP712 chain ID
    fn get_eip712_chain_id(env: Env) -> Bytes;

    /// Get EIP712 domain separator
    fn get_eip712_domain_separator(env: Env) -> Bytes;
}

// ==================== Initialization Functions ====================

/// Vault initialization configuration
#[contracttype]
#[derive(Clone, Debug)]
pub struct InitializeConfig {
    pub admin: Address,
    pub minter_manager: Address,
    pub token_contract: Address,
    pub oracle: Address,
    pub treasurer: Address,
    pub withdraw_verifier: Address,
    pub withdraw_fee_ratio: i128,
    pub withdraw_fee_receiver: Address,
    pub eip712_domain_name: String,
    pub eip712_domain_version: String,
}

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
        withdraw_fee_ratio: i128,
        withdraw_fee_receiver: Address,
        eip712_domain_name: String,
        eip712_domain_version: String,
    );

    /// Initialize contract with config (convenience method)
    fn initialize_with_config(env: Env, config: InitializeConfig) {
        Self::initialize(
            env,
            config.admin,
            config.minter_manager,
            config.token_contract,
            config.oracle,
            config.treasurer,
            config.withdraw_verifier,
            config.withdraw_fee_ratio,
            config.withdraw_fee_receiver,
            config.eip712_domain_name,
            config.eip712_domain_version,
        );
    }
}

// ==================== Event Definitions ====================

/// Deposit event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositEvent {
    pub user: Address,
    pub currency: Address,
    pub amount: i128,
    pub minted_tokens: i128,
    pub nav: i128,
}

/// Withdrawal event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawEvent {
    pub from: Address,
    pub shares: i128,
    pub gross_amount: i128,
    pub fee_amount: i128,
    pub actual_amount: i128,
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
