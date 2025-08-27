use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, Map, String, Symbol, Vec,
};

use stellar_ownable::{self as ownable, Ownable};
use stellar_ownable_macro::only_owner;
use stellar_default_impl_macro::default_impl;

// Import dependencies
use crate::dependencies::*;

// Signature verification uses Soroban SDK built-in functionality
use crate::traits::*;

// ==================== Constants ====================

/// Maximum number of supported currencies
const MAX_CURRENCIES: u32 = 10;

/// Fee precision (10000 = 100%)
const FEE_PRECISION: i128 = 10000;

/// EIP712 domain name as bytes
const EIP712_DOMAIN_NAME_BYTES: &[u8] = b"Solv Vault Withdraw";

/// EIP712 domain version as bytes
const EIP712_DOMAIN_VERSION_BYTES: &[u8] = b"1";


// ==================== Data Structures ====================

/// Storage data key enum
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    /// Oracle contract address
    Oracle,
    /// Treasurer address
    Treasurer,
    /// Withdrawal verifier public key (32 bytes)
    WithdrawVerifier,
    /// Token contract address
    TokenContract,
    /// Supported currencies mapping (Map<Address, bool>)
    AllowedCurrency,
    /// Deposit fee ratio
    DepositFeeRatio,
    /// Withdrawal currency
    WithdrawCurrency,
    /// Withdrawal fee ratio
    WithdrawFeeRatio,
    /// Withdraw fee receiver address
    WithdrawFeeReceiver,
    /// Withdrawal request status
    WithdrawRequestStatus,
    /// Used request hash mapping
    UsedRequestHash(Bytes),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracttype]
pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: Bytes,
    pub verifying_contract: Address,
    pub salt: Bytes,
}

/// Error code definition
#[contracterror]
#[derive(Clone, Debug, Copy, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    /// Invalid parameter
    InvalidArgument = 301,
    /// Currency not supported
    CurrencyNotAllowed = 302,
    /// Exceeds maximum currency quantity
    TooManyCurrencies = 303,
    /// Currency already exists
    CurrencyAlreadyExists = 304,
    /// Currency does not exist
    CurrencyNotExists = 305,
    /// Invalid amount
    InvalidAmount = 306,
    /// Oracle not set
    OracleNotSet = 307,
    /// Deposit fee ratio not set
    DepositFeeRatioNotSet = 308,
    /// Treasurer not set
    TreasurerNotSet = 309,
    /// Withdrawal verifier not set
    WithdrawVerifierNotSet = 310,
    /// Withdrawal currency not set
    WithdrawCurrencyNotSet = 311,
    /// Signature verification failed
    InvalidSignature = 312,
    /// Request hash already used
    RequestHashAlreadyUsed = 313,
    /// Invalid NAV
    InvalidNav = 314,
    /// Withdraw fee ratio not set
    WithdrawFeeRatioNotSet = 315,
    /// Invalid withdraw fee ratio
    InvalidWithdrawFeeRatio = 316,
    /// Withdraw fee receiver address not set
    WithdrawFeeReceiverNotSet = 317,
    /// NAV value expired
    StaleNavValue = 318,
    /// Invalid fee amount
    InvalidFeeAmount = 319,
    /// Token contract not set
    TokenContractNotSet = 320,
    /// Invalid signature format
    InvalidSignatureFormat = 321,
    /// Request already exists
    RequestAlreadyExists = 322,
    /// Insufficient balance
    InsufficientBalance = 323,
    /// Invalid request status
    InvalidRequestStatus = 324,
    /// Invalid deposit fee ratio
    InvalidDepositFeeRatio = 325,
   
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracttype]
pub enum WithdrawStatus {
    NotExist = 0,
    Pending = 1,
    Done = 2,
}

/// SolvBTC Vault contract
#[contract]
pub struct SolvBTCVault;

// ==================== Constructor ====================

#[contractimpl]
impl SolvBTCVault {
    /// Upgrade the contract with a new WASM hash
    #[only_owner]
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn __constructor(
        env: &Env,
        admin: Address,
        token_contract: Address,
        oracle: Address,
        treasurer: Address,
        withdraw_verifier: BytesN<32>,
        deposit_fee_ratio: i128,
        withdraw_fee_ratio: i128,
        withdraw_fee_receiver: Address,
        withdraw_currency: Address,
    ) {
        // Verify fee ratio
        if withdraw_fee_ratio < 0 || withdraw_fee_ratio > FEE_PRECISION {
            panic_with_error!(env, VaultError::InvalidWithdrawFeeRatio);
        }

        // Set contract owner using OpenZeppelin Ownable
        ownable::set_owner(env, &admin);
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
            .set(&DataKey::WithdrawFeeRatio, &withdraw_fee_ratio);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeReceiver, &withdraw_fee_receiver);
        env.storage()
            .instance()
            .set(&DataKey::DepositFeeRatio, &deposit_fee_ratio);
        
        // Set withdraw currency
        env.storage()
            .instance()
            .set(&DataKey::WithdrawCurrency, &withdraw_currency);

        // Publish initialization event
        env.events().publish(
            (Symbol::new(env, "initialize"),),
            (
                admin.clone(),
                oracle,
                treasurer,
                withdraw_verifier.clone(),
                withdraw_fee_ratio,
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
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        // Check if currency is supported
        if !Self::is_currency_supported_internal(&env, &currency) {
            panic_with_error!(env, VaultError::CurrencyNotAllowed);
        }

        // Get deposit fee ratio
        let deposit_fee_ratio = Self::get_deposit_fee_ratio_internal(&env);
        if deposit_fee_ratio <= 0 {
            panic_with_error!(env, VaultError::DepositFeeRatioNotSet);
        }

        // Calculate fee: fee = amount * depositFeeRatio / 10000
        let fee = (amount * deposit_fee_ratio) / 10000;
        let amount_after_fee = amount - fee;

        // Get NAV value
        let nav = Self::get_nav_from_oracle(&env);
        if nav <= 0 {
            panic_with_error!(env, VaultError::InvalidNav);
        }

        // Get treasurer address
        let treasurer = Self::get_treasurer_internal(&env);
        // Get currency decimals
        let currency_decimals = TokenClient::new(&env, &currency).decimals();
        // Get NAV decimals from Oracle
        let nav_decimals = Self::get_nav_decimals_from_oracle(&env);
        // Get token contract address
        let token_contract = Self::get_token_contract_internal(&env);
        // Get shares decimals
        let shares_decimals = TokenClient::new(&env, &token_contract).decimals();

        // Transfer from user to treasurer
        Self::transfer_from_user(&env, &currency, &from, &treasurer, amount);

        // Calculate the amount of tokens to be minted
        let minted_tokens = Self::calculate_mint_amount(
            &env,
            amount_after_fee,
            nav,
            currency_decimals,
            shares_decimals,
            nav_decimals,
        );

        // Directly mint shares using token contract; vault acts as minter (must be granted)
        TokenClient::new(&env, &token_contract).mint_from(
            &env.current_contract_address(),
            &from,
            &minted_tokens,
        );

        // Publish deposit event
        env.events().publish(
            (Symbol::new(&env, "deposit"), currency.clone(), from.clone()),
            DepositEvent {
                amount,
                minted_tokens,
                nav,
            },
        );

        minted_tokens
    }

    fn withdraw_request(env: Env, from: Address, shares: i128, request_hash: Bytes) {
        from.require_auth(); // Verify caller identity
                             // Verify parameters
        if shares <= 0 {
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        // Check configuration contains(oracle, withdraw fee receiver, withdraw fee ratio, withdraw currency, token contract)
        Self::validate_configuration(&env);

        // Get current nav from oracle
        let current_nav = Self::get_nav_from_oracle(&env);
        if current_nav <= 0 {
            panic_with_error!(env, VaultError::InvalidNav);
        }

        // Get withdraw token address (first supported currency)
        let withdraw_token: Address = Self::get_withdraw_currency_internal(&env);

        // Generate unique request key: second hash with all parameters (_msgSender, withdrawToken, requestHash, shares, nav)
        let request_key = Self::generate_request_key(
            &env,
            &from,
            &withdraw_token,
            &request_hash,
            shares,
            current_nav,
        );

        // Check if request already exists
        let current_status: WithdrawStatus = env
            .storage()
            .persistent()
            .get(&request_key)
            .unwrap_or(WithdrawStatus::NotExist);

        if current_status != WithdrawStatus::NotExist {
            panic_with_error!(env, VaultError::RequestAlreadyExists);
        }

        // Get token contract address
        let token_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap();

        // Check user has enough shares balance
        let token_client = TokenClient::new(&env, &token_contract);
        let user_balance = token_client.balance(&from);

        if user_balance < shares {
            panic_with_error!(env, VaultError::InsufficientBalance);
        }

        // Burn user's shares directly via token burn
        token_client.burn(&from, &shares);
        // Set withdraw request status to PENDING
        env.storage()
            .persistent()
            .set(&request_key, &WithdrawStatus::Pending);

        // Emit WithdrawRequest event
        env.events().publish(
            (Symbol::new(&env, "withdraw_request"), from.clone(), withdraw_token.clone()),
            WithdrawRequestEvent {
                token_contract,
                shares,
                request_hash,
                nav: current_nav,
            },
        );
    }

    fn withdraw(
        env: Env,
        from: Address,
        shares: i128,
        nav: i128,
        request_hash: Bytes,
        signature: BytesN<64>,
    ) -> i128 {
        from.require_auth(); // Verify caller identity

        // Verify parameters
        if shares <= 0 {
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        if nav <= 0 {
            panic_with_error!(env, VaultError::InvalidNav);
        }

        // Check configuration contains(oracle, withdraw fee receiver, withdraw fee ratio, withdraw currency, token contract)
        Self::validate_configuration(&env);

        // Get withdraw token address
        let withdraw_token: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap();

        // Get request key - second hash with all parameters (_msgSender, withdrawToken, requestHash, shares, nav)
        let request_key =
            Self::generate_request_key(&env, &from, &withdraw_token, &request_hash, shares, nav);

        // Check if request hash is already used
        let current_status: WithdrawStatus = env
            .storage()
            .persistent()
            .get(&request_key)
            .unwrap_or(WithdrawStatus::NotExist);

        // Only requests with Pending status can be processed
        if current_status != WithdrawStatus::Pending {
            panic_with_error!(env, VaultError::InvalidRequestStatus);
        }

        // Verify signature
        Self::verify_withdraw_signature(
            &env,
            &from,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
            &signature,
        );

        // Get fee ratio
        let withdraw_fee_ratio = Self::get_withdraw_fee_ratio_internal(&env);
        

        // Get token decimals for precise calculation
        let shares_token_decimals = Self::get_shares_token_decimals(&env);
        let withdraw_token_decimals = Self::get_withdraw_token_decimals(&env);
        let nav_decimals = Self::get_nav_decimals_from_oracle(&env);

        // Calculate withdrawal amount with proper decimal handling
        // amount = shares * nav * (10 ** withdrawTokenDecimals) / ((10 ** navDecimals) * (10 ** sharesTokenDecimals))
        let shares_precision = 10_i128.pow(shares_token_decimals);
        let nav_precision = 10_i128.pow(nav_decimals);
        let withdraw_precision = 10_i128.pow(withdraw_token_decimals);

        let amount = (shares * nav * withdraw_precision) / (nav_precision * shares_precision);

        // Calculate fee: fee = amount * withdrawFeeRatio / 10000
        let fee = (amount * withdraw_fee_ratio) / 10000;
        let amount_after_fee = amount - fee;

        // Set withdraw request status to DONE
        env.storage()
            .persistent()
            .set(&request_key, &WithdrawStatus::Done);

        // Get fee receiver address
        let fee_receiver: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawFeeReceiver)
            .unwrap();

        // Transfer fee to fee receiver
        if fee > 0 {
            Self::transfer_to_user(&env, &withdraw_token, &fee_receiver, fee);
        }

        // Transfer remaining amount to user
        Self::transfer_to_user(&env, &withdraw_token, &from, amount_after_fee);

        // Publish withdrawal event
        env.events().publish(
            (Symbol::new(&env, "withdraw"), from.clone(), withdraw_token.clone()),
            WithdrawEvent {
                amount: amount_after_fee,
                fee,
            },
        );

        amount_after_fee
    }

    fn treasurer_deposit(env: Env, amount: i128) {
        let treasurer = Self::get_treasurer_internal(&env);
        treasurer.require_auth(); // Verify caller identity

        // Verify parameters
        if amount <= 0 {
            panic_with_error!(env, VaultError::InvalidAmount); 
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
        env.events().publish(
            (Symbol::new(&env, "treasurer_deposit"), withdraw_currency.clone()),
            TreasurerDepositEvent {
                amount,
            },
        );
    }
}

// ==================== Currency management function implementation ====================

#[contractimpl]
impl CurrencyManagement for SolvBTCVault {
    #[only_owner]
    fn add_currency_by_admin(env: Env, currency: Address) {

        // Get current currency Map
        let mut currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedCurrency)
            .unwrap_or_else(|| Map::new(&env));

        // Check if exceeds maximum quantity
        if currencies.len() >= MAX_CURRENCIES {
            panic_with_error!(env, VaultError::TooManyCurrencies);
        }

        // Check if currency already exists
        if currencies.contains_key(currency.clone()) {
            panic_with_error!(env, VaultError::CurrencyAlreadyExists);
        }

        // Add currency
        currencies.set(currency.clone(), true);
        env.storage()
            .instance()
            .set(&DataKey::AllowedCurrency, &currencies);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "add_currency"), currency.clone()),
            SetAllowedCurrencyEvent {
                allowed: true,
            },
        );
    }

    #[only_owner]
    fn remove_currency_by_admin(env: Env, currency: Address) {

        // Get current currency Map
        let mut currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedCurrency)
            .unwrap_or_else(|| Map::new(&env));

        // Check if currency exists
        if !currencies.contains_key(currency.clone()) {
            panic_with_error!(env, VaultError::CurrencyNotExists);
        }

        // Remove currency
        currencies.remove(currency.clone());
        env.storage()
            .instance()
            .set(&DataKey::AllowedCurrency, &currencies);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "remove_currency"), currency.clone()),
            CurrencyRemovedEvent {
                admin: Self::get_admin_internal(&env),
            },
        );
    }

    fn get_supported_currencies(env: Env) -> Vec<Address> {
        let currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedCurrency)
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
    #[only_owner]
    fn set_withdraw_verifier_by_admin(env: Env, verifier_public_key: BytesN<32>) {

        env.storage()
            .instance()
            .set(&DataKey::WithdrawVerifier, &verifier_public_key);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_withdraw_verifier"), verifier_public_key.clone()),
            Self::get_admin_internal(&env)
        );
    }

    #[only_owner]
    fn set_oracle_by_admin(env: Env, oracle: Address) {
        env.storage().instance().set(&DataKey::Oracle, &oracle);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_oracle"), oracle.clone()),
            Self::get_admin_internal(&env)
        );
    }

    #[only_owner]
    fn set_treasurer_by_admin(env: Env, treasurer: Address) {
        env.storage()
            .instance()
            .set(&DataKey::Treasurer, &treasurer);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_treasurer"), treasurer.clone()),
            Self::get_admin_internal(&env)
        );
    }

    #[only_owner]
    fn set_deposit_fee_ratio_by_admin(env: Env, deposit_fee_ratio: i128) {
        // Verify fee ratio
        if deposit_fee_ratio < 0 || deposit_fee_ratio > FEE_PRECISION {
            panic_with_error!(env, VaultError::InvalidDepositFeeRatio);
        }

        env.storage()
            .instance()
            .set(&DataKey::DepositFeeRatio, &deposit_fee_ratio);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_deposit_fee_ratio"),),
            (Self::get_admin_internal(&env), deposit_fee_ratio)
        );
    }

    #[only_owner]
    fn set_withdraw_fee_ratio_by_admin(env: Env, withdraw_fee_ratio: i128) {

        // Verify fee ratio
        if withdraw_fee_ratio < 0 || withdraw_fee_ratio > FEE_PRECISION {
            panic_with_error!(env, VaultError::InvalidWithdrawFeeRatio);
        }

        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeRatio, &withdraw_fee_ratio);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_withdraw_fee_ratio"),),
            (Self::get_admin_internal(&env), withdraw_fee_ratio)
        );
    }

    fn set_withdraw_fee_recv_by_admin(env: Env, withdraw_fee_receiver: Address) {
        // This function already has #[only_owner] macro, no need for manual check
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeReceiver, &withdraw_fee_receiver);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_withdraw_fee_receiver"), withdraw_fee_receiver.clone()),
            Self::get_admin_internal(&env)
        );
    }

}

// ==================== Query function implementation ====================

#[contractimpl]
impl VaultQuery for SolvBTCVault {
    /// Get the current admin address
    fn get_admin(env: Env) -> Address {
        // Use the ownable trait to get owner
        // ownable::get_owner returns Option<Address>, unwrap it
        Self::get_admin_internal(&env)
    }

    fn get_withdraw_verifier(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawVerifier)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawVerifierNotSet))
    }

    fn get_oracle(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Oracle).unwrap()
    }

    fn get_treasurer(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasurer).unwrap()
    }

    fn get_withdraw_fee_ratio(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeRatio)
            .unwrap()
    }

    fn get_deposit_fee_ratio(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::DepositFeeRatio)
            .unwrap()
    }


    fn get_eip712_domain_name(env: Env) -> String {
        // Convert bytes constant to String
        String::from_bytes(&env, EIP712_DOMAIN_NAME_BYTES)
    }

    fn get_eip712_domain_version(env: Env) -> String {
        // Convert bytes constant to String
        String::from_bytes(&env, EIP712_DOMAIN_VERSION_BYTES)
    }

    fn get_eip712_chain_id(env: Env) -> Bytes {
        let network_id = env.ledger().network_id(); // Return BytesN<32>
                                                    // Directly return network_id, convert to Bytes type
        network_id.into()
    }

    fn get_eip712_domain_separator(env: Env) -> Bytes {
        Self::calculate_domain_separator(&env)
    }

    fn get_withdraw_fee_receiver(env: Env) -> Address {
        Self::get_withdraw_fee_receiver_internal(&env)
    }
}

// ==================== Internal helper functions ====================

impl SolvBTCVault {

    /// Create withdrawal message for signature verification
    fn create_withdraw_message(
        env: &Env,
        _user: &Address,
        target_amount: i128,
        target_token: &Address,
        nav: i128,
        request_hash: &Bytes,
    ) -> Bytes {
        let mut encoded = Bytes::new(env);

        // Add network ID (chain ID)
        let network_id = env.ledger().network_id();
        encoded.append(&network_id.into());

        // Add action (fixed as "withdraw")
        let action_bytes = Bytes::from_slice(env, b"withdraw");
        encoded.append(&action_bytes);

        // Add user address identifier
        encoded.append(&_user.to_xdr(env));

        // Add target currency
        encoded.append(&target_token.to_xdr(env));

        // Add target amount (shares)
        encoded.append(&Bytes::from_array(env, &target_amount.to_be_bytes()));

        // Add NAV value
        encoded.append(&Bytes::from_array(env, &nav.to_be_bytes()));

        // Add request hash
        encoded.append(request_hash);

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
        let type_hash = env.crypto().keccak256(&Bytes::from_slice(env,
            b"Withdraw(uint256 chainId,string action,address user,address withdrawToken,uint256 shares,uint256 nav,bytes32 requestHash)"));
        domain_encoded.append(&type_hash.into());

        // 2. name field's hash - use constant directly
        let name_bytes = Bytes::from_slice(env, EIP712_DOMAIN_NAME_BYTES);
        let name_hash = env.crypto().sha256(&name_bytes);
        domain_encoded.append(&name_hash.into());

        // 3. version field's hash - use constant directly  
        let version_bytes = Bytes::from_slice(env, EIP712_DOMAIN_VERSION_BYTES);
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
        public_key_bytes: &BytesN<32>,
        message: &Bytes,
        signature_bytes: &BytesN<64>,
    ) {
        // Call Soroban built-in ed25519 verification, if signature is invalid will panic
        env.crypto()
            .ed25519_verify(&public_key_bytes, message, &signature_bytes);
    }

    /// Get admin address (internal helper)
    fn get_admin_internal(env: &Env) -> Address {
        ownable::get_owner(env).unwrap()
    }

    /// Get verifier public key
    fn get_verifier_public_key(env: &Env) -> BytesN<32> {
        let verifier_public_key: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawVerifier)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawVerifierNotSet));

            verifier_public_key
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

    /// Get deposit fee ratio
    fn get_deposit_fee_ratio_internal(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::DepositFeeRatio)
            .unwrap_or(0) // Default to 0 (no fee)
    }

    /// Get withdrawal fee ratio
    fn get_withdraw_fee_ratio_internal(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeRatio)
            .unwrap_or(0) // Default to 0 (no fee)
    }

    /// Get withdrawal fee receiver
    fn get_withdraw_fee_receiver_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeReceiver)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawFeeReceiverNotSet))
    }

    /// Check if currency is supported
    fn is_currency_supported_internal(env: &Env, currency: &Address) -> bool {
        let currencies: Map<Address, bool> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedCurrency)
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
        OracleClient::new(env, &oracle_address).get_nav()
    }

    /// Get NAV decimals from Oracle contract
    fn get_nav_decimals_from_oracle(env: &Env) -> u32 {
        let oracle_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Oracle)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::OracleNotSet));

        // Call Oracle contract's get_nav_decimals method
        OracleClient::new(env, &oracle_address).get_nav_decimals()
    }

    /// Get shares token decimals
    fn get_shares_token_decimals(env: &Env) -> u32 {
        let shares_token: Address = env
            .storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap();

        TokenClient::new(env, &shares_token).decimals()
    }

    /// Get withdraw token decimals
    fn get_withdraw_token_decimals(env: &Env) -> u32 {
        let withdraw_token: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap();

        TokenClient::new(env, &withdraw_token).decimals()
    }

    /// Transfer from user
    fn transfer_from_user(env: &Env, token: &Address, from: &Address, to: &Address, amount: i128) {
        // Call token contract's transfer_from method
        TokenClient::new(env, token).transfer_from(
            &env.current_contract_address(),
            from,
            to,
            &amount,
        );
    }

    /// Transfer to user
    fn transfer_to_user(env: &Env, token: &Address, to: &Address, amount: i128) {
        // Call token contract's transfer method
        TokenClient::new(env, token).transfer(&env.current_contract_address(), to, &amount);
    }

    /// Verify withdrawal signature (using EIP712 standard)
    fn verify_withdraw_signature(
        env: &Env,
        user: &Address,
        target_amount: i128,
        target_token: &Address,
        nav: i128,
        request_hash: &Bytes,
        signature: &BytesN<64>,
    ) {
        // Check signature length
        if signature.len() != 64 {
            panic_with_error!(env, VaultError::InvalidSignatureFormat);
        }

        // Get verifier public key
        let verifier_public_key = Self::get_verifier_public_key(env);

        // 1. Create withdrawal message with action
        let withdraw_message = Self::create_withdraw_message(
            env,
            user,
            target_amount,
            target_token,
            nav,
            request_hash,
        );

        // 2. Calculate message hash
        let message_hash = env.crypto().sha256(&withdraw_message);
        let message_hash_bytes: Bytes = message_hash.into();

        // 3. Create EIP712 standard signature verification message: \x19\x01 + DomainSeparator + MessageHash
        let eip712_message = Self::create_eip712_signature_message(env, &message_hash_bytes);


        // Verify EIP712 standard signature (if signature is invalid will panic)
        Self::verify_ed25519_signature(
            env,
            &verifier_public_key,
            &eip712_message,
            &signature,
        );
    }

    // Calculate mint amount for user after user Deposit
    fn calculate_mint_amount(
        env: &Env,
        deposit_amount: i128,
        nav: i128,
        currency_decimals: u32,
        shares_decimals: u32,
        nav_decimals: u32,
    ) -> i128 {
        // shares = amount * (10^shares_decimals) * (10^nav_decimals) / (nav * (10^currency_decimals))
        let shares_precision = 10_i128.pow(shares_decimals);
        let nav_precision = 10_i128.pow(nav_decimals);
        let currency_precision = 10_i128.pow(currency_decimals);

        // Numerator: deposit_amount * shares_precision * nav_precision
        let numerator= deposit_amount
            .checked_mul(shares_precision)
            .and_then(|x| x.checked_mul(nav_precision))
            .unwrap_or_else(|| {
                panic_with_error!(env, VaultError::InvalidAmount);
            });

        // Denominator: nav * currency_precision
        let denominator = nav
            .checked_mul(currency_precision)
            .unwrap_or_else(|| {
                panic_with_error!(env, VaultError::InvalidAmount);
            });

        // Check for division by zero
        if denominator == 0 {
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        // Return result
        numerator / denominator
    }

    /// Validate configuration
    fn validate_configuration(env: &Env) {
        // Check Oracle
        if env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Oracle)
            .is_none()
        {
            panic_with_error!(env, VaultError::OracleNotSet);
        }

        // Check withdraw fee receiver
        if env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::WithdrawFeeReceiver)
            .is_none()
        {
            panic_with_error!(env, VaultError::WithdrawFeeReceiverNotSet);
        }

        // Check withdraw fee ratio
        let withdraw_fee_ratio: Option<i128> =
            env.storage().instance().get(&DataKey::WithdrawFeeRatio);
        if withdraw_fee_ratio.map_or(true, |r| r <= 0) {
            panic_with_error!(env, VaultError::WithdrawFeeRatioNotSet);
        }

        // Check withdraw currency
        if env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::WithdrawCurrency)
            .is_none()
        {
            panic_with_error!(env, VaultError::WithdrawCurrencyNotSet);
        }

        // Check token contract
        if env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::TokenContract)
            .is_none()
        {
            panic_with_error!(env, VaultError::TokenContractNotSet);
        }
    }

    /// Get token contract address
    fn get_token_contract_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::TokenContractNotSet))
    }


    /// Get EIP712 chain ID (internal function)
    fn get_eip712_chain_id_internal(env: &Env) -> Bytes {
        let network_id = env.ledger().network_id(); // Return BytesN<32>
                                                    // Directly return network_id, convert to Bytes type
        network_id.into()
    }

    /// Generate second hash key with all parameters (_msgSender, withdrawToken, requestHash, shares, nav)
    fn generate_request_key(
        env: &Env,
        from: &Address,
        withdraw_token: &Address,
        request_hash: &Bytes,
        shares: i128,
        nav: i128,
    ) -> Bytes {
        // Simple concatenation approach
        let mut data = Bytes::new(env);

        // Add from address as XDR bytes
        let from_xdr = from.to_xdr(env);
        data.append(&from_xdr);

        // Add withdraw_token address as XDR bytes
        let withdraw_token_xdr = withdraw_token.to_xdr(env);
        data.append(&withdraw_token_xdr);

        // Add request_hash
        data.append(request_hash);

        // Add shares as bytes (convert i128 to bytes)
        let shares_bytes = Bytes::from_array(env, &shares.to_be_bytes());
        data.append(&shares_bytes);

        // Add nav as bytes
        let nav_bytes = Bytes::from_array(env, &nav.to_be_bytes());
        data.append(&nav_bytes);

        // Hash the concatenated data
        let request_key_hash = env.crypto().keccak256(&data);
        Bytes::from_array(env, &request_key_hash.to_array())
    }
}

// ==================== Ownable Implementation ====================

#[default_impl]
#[contractimpl]
impl Ownable for SolvBTCVault {}
