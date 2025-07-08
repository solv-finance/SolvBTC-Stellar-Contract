use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, panic_with_error, symbol_short, vec,
    Address, Bytes, Env, FromVal, IntoVal, Map, Symbol, Vec,
};
use soroban_sdk::xdr::ToXdr;


// Signature verification uses Soroban SDK built-in functionality

use crate::traits::*;

// ==================== Constants ====================

/// Maximum number of supported currencies
const MAX_CURRENCIES: u32 = 10;

/// Fee precision (10000 = 100%)
const FEE_PRECISION: i128 = 10000;

// ==================== Data Structures ====================

/// Storage data key enum
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    /// Contract admin
    Admin,
    /// Initialization status
    Initialized,
    /// Minter Manager contract address
    MinterManager,
    /// Oracle contract address
    Oracle,
    /// Treasurer address
    Treasurer,
    /// Withdrawal verifier address
    WithdrawVerifier,
    /// Token contract address
    TokenContract,
    /// Supported currencies mapping (Map<Address, bool>)
    SupportedCurrencies,
    /// Withdrawal currency
    WithdrawCurrency,
    /// Withdrawal fee ratio
    WithdrawRatio,
    /// Fee collector address
    FeeCollector,
    /// Minimum fee amount
    MinimumFee,
    /// Used request hash (prevent replay attacks)
    UsedRequestHash(Bytes),
    /// EIP712 Domain name
    EIP712DomainName,
    /// EIP712 Domain version
    EIP712DomainVersion,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracttype]
pub struct EIP712Domain {
    pub name: soroban_sdk::String,
    pub version: soroban_sdk::String,
    pub chain_id: soroban_sdk::Bytes,
    pub verifying_contract: Address,
    pub salt: soroban_sdk::Bytes,
}

/// Error code definition
#[contracterror]
#[derive(Clone, Debug, Copy, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    /// Permission insufficient
    Unauthorized = 1,
    /// Invalid parameter
    InvalidArgument = 2,
    /// Contract not initialized
    NotInitialized = 3,
    /// Contract already initialized
    AlreadyInitialized = 4,
    /// Currency not supported
    CurrencyNotSupported = 5,
    /// Exceeds maximum currency quantity
    TooManyCurrencies = 6,
    /// Currency already exists
    CurrencyAlreadyExists = 7,
    /// Currency does not exist
    CurrencyNotExists = 8,
    /// Invalid amount
    InvalidAmount = 9,
    /// Oracle not set
    OracleNotSet = 10,
    /// Minter Manager not set
    MinterManagerNotSet = 11,
    /// Treasurer not set
    TreasurerNotSet = 12,
    /// Withdrawal verifier not set
    WithdrawVerifierNotSet = 13,
    /// Withdrawal currency not set
    WithdrawCurrencyNotSet = 14,
    /// Signature verification failed
    InvalidSignature = 15,
    /// Request hash already used
    RequestHashAlreadyUsed = 16,
    /// Invalid NAV
    InvalidNav = 17,
    /// Invalid withdraw fee ratio
    InvalidWithdrawRatio = 18,
    /// Fee collector address not set
    FeeCollectorNotSet = 19,
    /// NAV value expired
    StaleNavValue = 20,
    /// Invalid fee amount
    InvalidFeeAmount = 21,
    /// Token contract not set
    TokenContractNotSet = 22,
    /// Invalid signature format
    InvalidSignatureFormat = 23,
}

/// SolvBTC Vault contract
#[contract]
pub struct SolvBTCVault;

// ==================== Initialization function implementation ====================

#[contractimpl]
impl VaultInitialization for SolvBTCVault {
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
    ) {
        // Check if already initialized
        if Self::is_initialized_internal(&env) {
            panic_with_error!(&env, VaultError::AlreadyInitialized);
        }

        // Verify admin permission
        admin.require_auth();

        // Verify fee ratio
        if withdraw_ratio < 0 || withdraw_ratio > FEE_PRECISION {
            panic_with_error!(&env, VaultError::InvalidWithdrawRatio);
        }

        // Set contract status
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::MinterManager, &minter_manager);
        env.storage()
            .instance()
            .set(&DataKey::TokenContract, &token_contract);
        env.storage().instance().set(&DataKey::Oracle, &oracle);
        env.storage()
            .instance()
            .set(&DataKey::Treasurer, &treasurer);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawVerifier, &withdraw_verifier);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawRatio, &withdraw_ratio);
        // Initialize empty currency Map
        let empty_currencies: Map<Address, bool> = Map::new(&env);
        env.storage()
            .instance()
            .set(&DataKey::SupportedCurrencies, &empty_currencies);

        // Set EIP712 domain parameter default values
        env.storage()
            .instance()
            .set(&DataKey::EIP712DomainName, &eip712_domain_name);
        env.storage()
            .instance()
            .set(&DataKey::EIP712DomainVersion, &eip712_domain_version);

        // Mark as initialized
        env.storage().instance().set(&DataKey::Initialized, &true);

        // Publish initialization event
        env.events().publish(
            (symbol_short!("init"),),
            (
                admin.clone(),
                minter_manager,
                oracle,
                treasurer,
                withdraw_verifier.clone(),
                withdraw_ratio,
            ),
        );
    }
}

// ==================== Deposit and withdrawal function implementation ====================

#[contractimpl]
impl VaultOperations for SolvBTCVault {
    fn deposit(env: Env, from: Address, currency: Address, amount: i128) -> i128 {
        from.require_auth(); // Verify caller identity

        // Verify parameters
        if amount <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        // Check if currency is supported
        if !Self::is_currency_supported_internal(&env, &currency) {
            panic_with_error!(&env, VaultError::CurrencyNotSupported);
        }
        let treasurer = Self::get_treasurer_internal(&env);

        // Transfer from user to treasurer
        Self::transfer_from_user(&env, &currency, &from, &treasurer, amount);

        // Get NAV value and Decimals
        let nav = Self::get_nav_from_oracle(&env);
        if nav <= 0 {
            panic_with_error!(&env, VaultError::InvalidNav);
        }

        // Calculate the amount of tokens to be minted
        let minted_tokens = Self::calculate_mint_amount(&env, amount, nav);
        // Get token contract address
        let token_contract = Self::get_token_contract_internal(&env);
        // Call Minter Manager to mint tokens
        Self::mint_tokens(
            &env,
            &env.current_contract_address(),
            &from,
            token_contract.clone(),
            minted_tokens,
        );

        // Publish deposit event
        env.events().publish(
            (symbol_short!("deposit"),),
            DepositEvent {
                user: from.clone(),
                currency: currency.clone(),
                amount,
                token_contract,
                minted_tokens,
                nav,
            },
        );

        minted_tokens
    }

    fn withdraw(
        env: Env,
        from: Address,
        target_amount: i128,
        nav: i128,
        request_hash: Bytes,
        timestamp: u64,
        signature: Bytes,
    ) -> i128 {
        from.require_auth(); // Verify caller identity

        // Verify parameters
        if target_amount <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        if nav <= 0 {
            panic_with_error!(&env, VaultError::InvalidNav);
        }

        // Check if request hash is already used
        if Self::is_request_hash_used(&env, &request_hash) {
            panic_with_error!(&env, VaultError::RequestHashAlreadyUsed);
        }

        // Get withdrawal currency
        let withdraw_currency = Self::get_withdraw_currency_internal(&env);

        // Verify signature
        Self::verify_withdraw_signature(
            &env,
            &from,
            target_amount,
            &withdraw_currency,
            nav,
            &request_hash,
            timestamp,
            &signature,
        );

        // Get fee ratio
        let withdraw_ratio = Self::get_withdraw_ratio_internal(&env);

        // Calculate actual withdrawal amount (based on NAV)
        let gross_amount = Self::calculate_withdraw_amount(&env, target_amount, nav);

        // Calculate fee
        let fee_amount = (gross_amount * withdraw_ratio) / FEE_PRECISION;
        let actual_amount = gross_amount - fee_amount;

        // Calculate the amount of tokens to be burned
        let burned_tokens = target_amount;
        // Get contract address
        let vault_address = env.current_contract_address();
        // Burn user's tokens
        let token_contract = Self::get_token_contract_internal(&env);
        Self::burn_tokens(&env, &vault_address, token_contract, burned_tokens);

        // Transfer to user
        Self::transfer_to_user(&env, &withdraw_currency, &from, actual_amount);

        // Mark request hash as used
        env.storage()
            .instance()
            .set(&DataKey::UsedRequestHash(request_hash.clone()), &true);

        // Publish withdrawal event
        env.events().publish(
            (symbol_short!("withdraw"),),
            WithdrawEvent {
                from: from.clone(),
                target_amount,
                gross_amount,
                fee_amount,
                actual_amount,
                burned_tokens,
                nav,
                request_hash: request_hash.clone(),
            },
        );

        actual_amount
    }

    fn treasurer_deposit(env: Env, amount: i128) {
        let treasurer = Self::get_treasurer_internal(&env);
        treasurer.require_auth(); // Verify caller identity

        // Verify parameters
        if amount <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        // Get withdrawal currency
        let withdraw_currency = Self::get_withdraw_currency_internal(&env);

        // Treasurer deposits liquidity (this can be implemented based on specific requirements)
        // Assuming transfer from treasurer to contract address
        let contract_address = env.current_contract_address();
        Self::transfer_from_user(
            &env,
            &withdraw_currency,
            &treasurer,
            &contract_address,
            amount,
        );

        // Publish event
        env.events()
            .publish((symbol_short!("tres_dep"),), (treasurer, amount));
    }
}

// ==================== Currency management function implementation ====================

#[contractimpl]
impl CurrencyManagement for SolvBTCVault {
    fn add_currency_by_admin(env: Env, currency: Address) {
        let admin = Self::require_admin(&env);

        // Get current currency Map
        let mut currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::SupportedCurrencies)
            .unwrap_or_else(|| Map::new(&env));

        // Check if exceeds maximum quantity
        if currencies.len() >= MAX_CURRENCIES {
            panic_with_error!(&env, VaultError::TooManyCurrencies);
        }

        // Check if currency already exists
        if currencies.contains_key(currency.clone()) {
            panic_with_error!(&env, VaultError::CurrencyAlreadyExists);
        }

        // Add currency
        currencies.set(currency.clone(), true);
        env.storage()
            .instance()
            .set(&DataKey::SupportedCurrencies, &currencies);

        // Publish event
        env.events().publish(
            (symbol_short!("curr_add"),),
            CurrencyAddedEvent {
                admin,
                currency: currency.clone(),
            },
        );
    }

    fn remove_currency_by_admin(env: Env, currency: Address) {
        let admin = Self::require_admin(&env);

        // Get current currency Map
        let mut currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::SupportedCurrencies)
            .unwrap_or_else(|| Map::new(&env));

        // Check if currency exists
        if !currencies.contains_key(currency.clone()) {
            panic_with_error!(&env, VaultError::CurrencyNotExists);
        }

        // Remove currency
        currencies.remove(currency.clone());
        env.storage()
            .instance()
            .set(&DataKey::SupportedCurrencies, &currencies);

        // Publish event
        env.events().publish(
            (symbol_short!("curr_rm"),),
            CurrencyRemovedEvent {
                admin,
                currency: currency.clone(),
            },
        );
    }

    fn set_withdraw_currency_by_admin(env: Env, currency: Address) {
        Self::require_admin(&env);

        // Check if currency is supported
        if !Self::is_currency_supported_internal(&env, &currency) {
            panic_with_error!(&env, VaultError::CurrencyNotSupported);
        }

        env.storage()
            .instance()
            .set(&DataKey::WithdrawCurrency, &currency);

        // Publish event
        env.events().publish(
            (symbol_short!("wd_curr"),),
            (Self::get_admin_internal(&env), currency),
        );
    }

    fn get_supported_currencies(env: Env) -> Vec<Address> {
        let currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::SupportedCurrencies)
            .unwrap_or_else(|| Map::new(&env));
        currencies.keys()
    }

    fn is_currency_supported(env: Env, currency: Address) -> bool {
        Self::is_currency_supported_internal(&env, &currency)
    }

    fn get_withdraw_currency(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::WithdrawCurrency)
    }
}

// ==================== System management function implementation ====================

#[contractimpl]
impl SystemManagement for SolvBTCVault {
    fn set_withdraw_verifier_by_admin(env: Env, verifier_address: Address) {
        Self::require_admin(&env);

        env.storage()
            .instance()
            .set(&DataKey::WithdrawVerifier, &verifier_address);

        // Publish event
        env.events().publish(
            (symbol_short!("wd_verif"),),
            (Self::get_admin_internal(&env), verifier_address.clone()),
        );
    }

    fn set_oracle_by_admin(env: Env, oracle: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Oracle, &oracle);

        // Publish event
        env.events().publish(
            (symbol_short!("oracle"),),
            (Self::get_admin_internal(&env), oracle),
        );
    }

    fn set_treasurer_by_admin(env: Env, treasurer: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::Treasurer, &treasurer);

        // Publish event
        env.events().publish(
            (symbol_short!("treasur"),),
            (Self::get_admin_internal(&env), treasurer),
        );
    }

    fn set_minter_manager_by_admin(env: Env, minter_manager: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::MinterManager, &minter_manager);

        // Publish event
        env.events().publish(
            (symbol_short!("minter"),),
            (Self::get_admin_internal(&env), minter_manager),
        );
    }

    fn set_withdraw_ratio_by_admin(env: Env, withdraw_ratio: i128) {
        Self::require_admin(&env);

        // Verify fee ratio
        if withdraw_ratio < 0 || withdraw_ratio > FEE_PRECISION {
            panic_with_error!(&env, VaultError::InvalidWithdrawRatio);
        }

        env.storage()
            .instance()
            .set(&DataKey::WithdrawRatio, &withdraw_ratio);

        // Publish event
        env.events().publish(
            (symbol_short!("wd_ratio"),),
            (Self::get_admin_internal(&env), withdraw_ratio),
        );
    }

    fn set_eip712_domain_by_admin(
        env: Env,
        name: soroban_sdk::String,
        version: soroban_sdk::String,
    ) {
        Self::require_admin(&env);

        // Set EIP712 domain parameter
        env.storage()
            .instance()
            .set(&DataKey::EIP712DomainName, &name);
        env.storage()
            .instance()
            .set(&DataKey::EIP712DomainVersion, &version);

        // Publish event
        env.events().publish(
            (symbol_short!("eip712"),),
            (Self::get_admin_internal(&env), name.clone(), version),
        );
    }
}

// ==================== Query function implementation ====================

#[contractimpl]
impl VaultQuery for SolvBTCVault {
    fn admin(env: Env) -> Address {
        Self::get_admin_internal(&env)
    }

    fn get_withdraw_verifier(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawVerifier)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::WithdrawVerifierNotSet))
    }

    fn get_oracle(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Oracle).unwrap()
    }

    fn get_treasurer(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasurer).unwrap()
    }

    fn get_minter_manager(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::MinterManager)
            .unwrap()
    }

    fn get_withdraw_ratio(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawRatio)
            .unwrap()
    }

    fn is_initialized(env: Env) -> bool {
        Self::is_initialized_internal(&env)
    }

    fn get_eip712_domain_name(env: Env) -> soroban_sdk::String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainName)
            .unwrap_or_else(|| soroban_sdk::String::from_str(&env, "SolvBTC Vault"))
    }

    fn get_eip712_domain_version(env: Env) -> soroban_sdk::String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainVersion)
            .unwrap_or_else(|| soroban_sdk::String::from_str(&env, "1"))
    }

    fn get_eip712_chain_id(env: Env) -> soroban_sdk::Bytes {
        let network_id = env.ledger().network_id(); // Return BytesN<32>
                                                    // Directly return network_id, convert to Bytes type
        network_id.into()
    }

    fn get_eip712_domain_separator(env: Env) -> soroban_sdk::Bytes {
        Self::calculate_domain_separator(&env)
    }
}

// ==================== Internal helper functions ====================

impl SolvBTCVault {
    /// Check if contract is initialized
    fn is_initialized_internal(env: &Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    /// Create withdrawal message for signature verification
    fn create_withdraw_message(
        env: &Env,
        _user: &Address,
        target_amount: i128,
        target_token: &Address,
        nav: i128,
        request_hash: &Bytes,
        timestamp: u64,
    ) -> Bytes {
        let mut encoded = Bytes::new(env);

        // Add user address identifier
        encoded.append(&_user.to_xdr(env));

        // Add target amount
        encoded.append(&Bytes::from_array(env, &target_amount.to_be_bytes()));

        // Add target currency
        encoded.append(&target_token.to_xdr(env));

        // Use request hash to identify user, avoid complex address conversion
        let user_hash = env.crypto().sha256(request_hash);
        encoded.append(&user_hash.into());

        // Add NAV value
        encoded.append(&Bytes::from_array(env, &nav.to_be_bytes()));

        // Add request hash
        encoded.append(request_hash);

        // Add timestamp
        encoded.append(&Bytes::from_array(env, &timestamp.to_be_bytes()));

        encoded
    }

    // Create EIP712 standard signature verification message: \x19\x01 + DomainSeparator + MessageHash
    fn create_eip712_signature_message(env: &Env, message_hash: &Bytes) -> Bytes {
        let mut encoded = Bytes::new(env);

        // 1. Add EIP712 fixed prefix \x19\x01
        encoded.append(&Bytes::from_slice(env, &[0x19, 0x01]));

        // 2. Calculate and add DomainSeparator
        let domain_separator = Self::calculate_domain_separator(env);
        encoded.append(&domain_separator);

        // 3. Add MessageHash
        encoded.append(message_hash);

        encoded
    }

    // Calculate EIP712 DomainSeparator
    fn calculate_domain_separator(env: &Env) -> Bytes {
        // Implement domain separator calculation according to EIP712 standard
        // DomainSeparator = keccak256(typeHash + nameHash + versionHash + chainId + verifyingContract + salt)

        let mut domain_encoded = Bytes::new(env);

        // 1. EIP712Domain's TypeHash
        // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
        let type_hash = env.crypto().sha256(&Bytes::from_slice(env,
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"));
        domain_encoded.append(&type_hash.into());

        // 2. name field's hash
        // Get domain name from storage
        let name = Self::get_eip712_domain_name_internal(env);

        // Use copy_into_slice method to copy String content to byte array
        let name_len = name.len() as usize;
        // Create fixed-size buffer
        let mut name_buffer = [0u8; 100]; // Use sufficiently large buffer
                                          // Copy String content to buffer
        name.copy_into_slice(&mut name_buffer[..name_len]);

        // Convert byte array to Bytes
        let name_bytes = Bytes::from_slice(env, &name_buffer[..name_len]);
        let name_hash = env.crypto().sha256(&name_bytes);
        domain_encoded.append(&name_hash.into());

        // 3. version field's hash
        // Get domain version from storage
        let version = Self::get_eip712_domain_version_internal(env);

        // Use copy_into_slice method to copy String content to byte array
        let version_len = version.len() as usize;
        // Create fixed-size buffer
        let mut version_buffer = [0u8; 20]; // Use sufficiently large buffer
                                            // Copy String content to buffer
        version.copy_into_slice(&mut version_buffer[..version_len]);

        // Convert byte array to Bytes
        let version_bytes = Bytes::from_slice(env, &version_buffer[..version_len]);
        let version_hash = env.crypto().sha256(&version_bytes);
        domain_encoded.append(&version_hash.into());

        // 4. chainId field (32 bytes)
        let chain_id = Self::get_eip712_chain_id_internal(env);
        domain_encoded.append(&chain_id);

        // 5. verifyingContract field's hash
        let verifying_contract = env.current_contract_address();
        // Directly use byte representation of contract address
        let contract_xdr = verifying_contract.to_xdr(env);
        let contract_hash = env.crypto().sha256(&contract_xdr);
        domain_encoded.append(&contract_hash.into());

        // 6. salt field (32 bytes of zero value)
        let salt = Bytes::from_array(env, &[0u8; 32]);
        domain_encoded.append(&salt);

        // Return domain separator's hash (according to EIP712 standard should use keccak256, but Soroban uses sha256)
        env.crypto().sha256(&domain_encoded).into()
    }
    /// Ed25519 signature verification function, using Soroban SDK built-in functionality
    fn verify_ed25519_signature(
        env: &Env,
        public_key_bytes: &[u8; 32],
        message: &Bytes,
        signature_bytes: &[u8; 64],
    ) {
        // Use Soroban SDK built-in ed25519_verify function
        let public_key = soroban_sdk::BytesN::from_array(env, public_key_bytes);
        let signature = soroban_sdk::BytesN::from_array(env, signature_bytes);

        // Call Soroban built-in ed25519 verification, if signature is invalid will panic
        env.crypto()
            .ed25519_verify(&public_key, message, &signature);
    }

    /// Get verifier public key
    fn get_verifier_public_key(env: &Env) -> [u8; 32] {
        let verifier_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawVerifier)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawVerifierNotSet));

        // Extract public key bytes from Address
        // Note: Here we assume Address is of Ed25519 public key type
        let address_xdr = verifier_address.to_xdr(env);

        // Extract public key from XDR (last 32 bytes of Address)
        let mut public_key = [0u8; 32];
        let xdr_len = address_xdr.len();
        if xdr_len >= 32 {
            for i in 0..32 {
                let index = xdr_len - 32 + (i as u32);
                public_key[i] = address_xdr.get(index).unwrap();
            }
        } else {
            panic_with_error!(env, VaultError::InvalidArgument);
        }

        public_key
    }

    /// Get admin address
    fn get_admin_internal(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Verify admin permission
    fn require_admin(env: &Env) -> Address {
        let admin = Self::get_admin_internal(env);
        admin.require_auth();
        admin
    }

    /// Get treasurer address
    fn get_treasurer_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Treasurer)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::TreasurerNotSet))
    }

    /// Get withdrawal currency
    fn get_withdraw_currency_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawCurrencyNotSet))
    }

    /// Get withdrawal fee ratio
    fn get_withdraw_ratio_internal(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawRatio)
            .unwrap_or(0) // Default to 0 (no fee)
    }

    /// Check if currency is supported
    fn is_currency_supported_internal(env: &Env, currency: &Address) -> bool {
        let currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::SupportedCurrencies)
            .unwrap_or_else(|| Map::new(env));
        currencies.contains_key(currency.clone())
    }

    /// Get NAV value from Oracle
    fn get_nav_from_oracle(env: &Env) -> i128 {
        let oracle_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Oracle)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::OracleNotSet));

        // Call Oracle contract's get_nav method
        env.invoke_contract(
            &oracle_address,
            &Symbol::new(env, "get_nav"),
            soroban_sdk::vec![env],
        )
    }

    /// Get NAV decimals from Oracle
    fn get_nav_decimals_from_oracle(env: &Env) -> u32 {
        let oracle_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Oracle)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::OracleNotSet));

        // Call Oracle contract's get_nav_decimals method
        env.invoke_contract(
            &oracle_address,
            &Symbol::new(env, "get_nav_decimals"),
            soroban_sdk::vec![env],
        )
    }

    /// Mint tokens
    fn mint_tokens(env: &Env, from: &Address, to: &Address, token_contract: Address, amount: i128) {
        let minter_manager: Address = env
            .storage()
            .instance()
            .get(&DataKey::MinterManager)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::MinterManagerNotSet));

        // Call Minter Manager's mint method
        let _result: () = env.invoke_contract(
            &minter_manager,
            &Symbol::new(env, "mint"),
            (from.clone(), token_contract, to, amount).into_val(env),
        );
    }

    /// Burn tokens
    fn burn_tokens(env: &Env, from: &Address, token_contract: Address, amount: i128) {
        let minter_manager: Address = env
            .storage()
            .instance()
            .get(&DataKey::MinterManager)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::MinterManagerNotSet));

        // Call Minter Manager's burn method
        let _result: () = env.invoke_contract(
            &minter_manager,
            &Symbol::new(env, "burn"),
            (from.clone(), token_contract, amount).into_val(env),
        );
    }

    /// Transfer from user
    fn transfer_from_user(env: &Env, token: &Address, from: &Address, to: &Address, amount: i128) {
        // Call token contract's transfer_from method
        let _result: () = env.invoke_contract(
            token,
            &Symbol::new(env, "transfer_from"),
            (env.current_contract_address(), from, to, amount).into_val(env),
        );
    }

    /// Transfer to user
    fn transfer_to_user(env: &Env, token: &Address, to: &Address, amount: i128) {
        // Call token contract's transfer method
        let _result: () = env.invoke_contract(
            token,
            &Symbol::new(env, "transfer"),
            (env.current_contract_address(), to, amount).into_val(env),
        );
    }

    /// Verify withdrawal signature (using EIP712 standard)
    fn verify_withdraw_signature(
        env: &Env,
        user: &Address,
        target_amount: i128,
        target_token: &Address,
        nav: i128,
        request_hash: &Bytes,
        timestamp: u64,
        signature: &Bytes,
    ) {
        // Check signature length
        if signature.len() != 64 {
            panic_with_error!(env, VaultError::InvalidSignatureFormat);
        }

        // Get verifier public key
        let verifier_public_key = Self::get_verifier_public_key(env);

        // 1. Create withdrawal message
        let withdraw_message = Self::create_withdraw_message(
            env,
            user,
            target_amount,
            target_token,
            nav,
            request_hash,
            timestamp,
        );

        // 2. Calculate message hash
        let message_hash = env.crypto().sha256(&withdraw_message);
        let message_hash_bytes: Bytes = message_hash.into();

        // 3. Create EIP712 standard signature verification message: \x19\x01 + DomainSeparator + MessageHash
        let eip712_message = Self::create_eip712_signature_message(env, &message_hash_bytes);

        // Convert signature from Bytes to array
        let mut signature_array = [0u8; 64];
        for i in 0..64 {
            signature_array[i] = signature.get(i as u32).unwrap();
        }

        // Verify EIP712 standard signature (if signature is invalid will panic)
        Self::verify_ed25519_signature(
            env,
            &verifier_public_key,
            &eip712_message,
            &signature_array,
        );
    }

    /// Check if request hash is already used
    fn is_request_hash_used(env: &Env, request_hash: &Bytes) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::UsedRequestHash(request_hash.clone()))
    }

    // Calculate mint amount for user after user Deposit
    fn calculate_mint_amount(env: &Env, amount: i128, nav: i128) -> i128 {
        // Get NAV decimals from Oracle
        let nav_decimals = Self::get_nav_decimals_from_oracle(env);
        let precision = 10_i128.pow(nav_decimals);
        amount * nav / precision
    }

    /// Calculate withdrawal amount
    fn calculate_withdraw_amount(env: &Env, target_amount: i128, nav: i128) -> i128 {
        // Get NAV decimals from Oracle
        let nav_decimals = Self::get_nav_decimals_from_oracle(env);

        // Calculate precision divisor: 10^nav_decimals
        let precision = 10_i128.pow(nav_decimals);

        // Calculate actual amount: target_amount * nav / precision
        target_amount * nav / precision
    }

    fn get_token_contract_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::TokenContractNotSet))
    }

    /// Get EIP712 domain name (internal function)
    fn get_eip712_domain_name_internal(env: &Env) -> soroban_sdk::String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainName)
            .unwrap_or_else(|| soroban_sdk::String::from_str(env, "SolvBTC Vault"))
    }

    /// Get EIP712 domain version (internal function)
    fn get_eip712_domain_version_internal(env: &Env) -> soroban_sdk::String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainVersion)
            .unwrap_or_else(|| soroban_sdk::String::from_str(env, "1"))
    }

    /// Get EIP712 chain ID (internal function)
    fn get_eip712_chain_id_internal(env: &Env) -> soroban_sdk::Bytes {
        let network_id = env.ledger().network_id(); // Return BytesN<32>
                                                    // Directly return network_id, convert to Bytes type
        network_id.into()
    }
}