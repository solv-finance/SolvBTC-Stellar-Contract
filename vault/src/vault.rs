use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, FromVal, IntoVal, Map, String, Symbol, Vec,
};

// Import dependencies
use crate::dependencies::*;

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
    WithdrawFeeRatio,
    /// Withdraw fee receiver address
    WithdrawFeeReceiver,
    /// Withdrawal request status
    WithdrawRequestStatus,
    /// EIP712 Domain name
    EIP712DomainName,
    /// EIP712 Domain version
    EIP712DomainVersion,
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
    /// Withdraw fee ratio not set
    WithdrawFeeRatioNotSet = 18,
    /// Invalid withdraw fee ratio
    InvalidWithdrawFeeRatio = 19,
    /// Withdraw fee receiver address not set
    WithdrawFeeReceiverNotSet = 20,
    /// NAV value expired
    StaleNavValue = 21,
    /// Invalid fee amount
    InvalidFeeAmount = 22,
    /// Token contract not set
    TokenContractNotSet = 23,
    /// Invalid signature format
    InvalidSignatureFormat = 24,
    /// Request already exists
    RequestAlreadyExists = 25,
    /// Insufficient balance
    InsufficientBalance = 26,
    /// Invalid request status
    InvalidRequestStatus = 27,
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
        withdraw_fee_ratio: i128,
        withdraw_fee_receiver: Address,
        eip712_domain_name: String,
        eip712_domain_version: String,
    ) {
        // Verify admin permission
        admin.require_auth();

        // Check if already initialized
        if Self::is_initialized_internal(&env) {
            panic_with_error!(&env, VaultError::AlreadyInitialized);
        }

        // Verify fee ratio
        if withdraw_fee_ratio < 0 || withdraw_fee_ratio > FEE_PRECISION {
            panic_with_error!(&env, VaultError::InvalidWithdrawFeeRatio);
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
            .set(&DataKey::WithdrawFeeRatio, &withdraw_fee_ratio);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeReceiver, &withdraw_fee_receiver);
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
            (Symbol::new(&env, "init"),),
            (
                admin.clone(),
                minter_manager,
                oracle,
                treasurer,
                withdraw_verifier.clone(),
                withdraw_fee_ratio,
            ),
        );
    }

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
        )
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

        // Check if withdraw fee ratio is set
        if Self::get_withdraw_fee_ratio_internal(&env) <= 0 {
            panic_with_error!(&env, VaultError::WithdrawFeeReceiverNotSet);
        }

        // Check if withdraw fee receiver is set
        Self::get_withdraw_fee_receiver_internal(&env);

        // Get NAV value
        let nav = Self::get_nav_from_oracle(&env);
        if nav <= 0 {
            panic_with_error!(&env, VaultError::InvalidNav);
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
        // Calculate the amount of tokens to be minted
        let minted_tokens = Self::calculate_mint_amount(
            amount,
            nav,
            currency_decimals,
            shares_decimals,
            nav_decimals,
        );

        // Transfer from user to treasurer
        Self::transfer_from_user(&env, &currency, &from, &treasurer, amount);

        // Call Minter Manager to mint tokens
        Self::mint_tokens(&env, &env.current_contract_address(), &from, minted_tokens);

        // Publish deposit event
        env.events().publish(
            (Symbol::new(&env, "deposit"),),
            DepositEvent {
                user: from.clone(),
                currency: currency.clone(),
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
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        // Check configuration contains(oracle, withdraw fee receiver, withdraw fee ratio, withdraw currency, token contract)
        Self::validate_configuration(&env);

        // Get current nav from oracle
        let current_nav = Self::get_nav_from_oracle(&env);
        if current_nav <= 0 {
            panic_with_error!(&env, VaultError::InvalidNav);
        }

        // Get withdraw token address
        let withdraw_token: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap();

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
            panic_with_error!(&env, VaultError::RequestAlreadyExists);
        }

        // Get token contract address
        let token_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap();

        // Check user has enough shares balance
        let token_client = TokenClient::new(&env, &token_contract);
        let user_balance = token_client.balance_of(&from);

        if user_balance < shares {
            panic_with_error!(&env, VaultError::InsufficientBalance);
        }

        // Use minter_manager burn user's shares
        let spender = env.current_contract_address();
        let minter_manager = Self::get_minter_manager_internal(&env);
        
        // Step 1: Transfer tokens from user to Vault (user has already approved Vault)
        token_client.transfer_from(&spender, &from, &spender, &shares);
        
        // Step 2: Vault approves MinterManager to transfer tokens from Vault
        token_client.approve(&spender, &minter_manager, &shares);
        
        // Step 3: MinterManager burns Vault's shares (this will call transfer_from internally)
        Self::burn_tokens(&env, &spender, shares);
        // Set withdraw request status to PENDING
        env.storage()
            .persistent()
            .set(&request_key, &WithdrawStatus::Pending);

        // Emit WithdrawRequest event
        env.events().publish(
            (Symbol::new(&env, "WithdrawRequest"),),
            (from, withdraw_token, shares, request_hash, current_nav),
        );
    }

    fn withdraw(
        env: Env,
        from: Address,
        shares: i128,
        nav: i128,
        request_hash: Bytes,
        timestamp: u64,
        signature: Bytes,
    ) -> i128 {
        from.require_auth(); // Verify caller identity

        // Verify parameters
        if shares <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        if nav <= 0 {
            panic_with_error!(&env, VaultError::InvalidNav);
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
            panic_with_error!(&env, VaultError::InvalidRequestStatus);
        }

        // Verify signature
        Self::verify_withdraw_signature(
            &env,
            &from,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
            timestamp,
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
            (Symbol::new(&env, "withdraw"),),
            WithdrawEvent {
                from: from.clone(),
                shares,
                gross_amount: amount,
                fee_amount: fee,
                actual_amount: amount_after_fee,
                nav,
                request_hash: request_hash.clone(),
            },
        );

        amount_after_fee
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
        env.events().publish(
            (Symbol::new(&env, "treasurer_deposit"),),
            (treasurer, amount),
        );
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
            (Symbol::new(&env, "add_currency"),),
            CurrencyAddedEvent {
                admin,
                currency: currency.clone(),
            },
        );
    }

    fn remove_currency_by_admin(env: Env, currency: Address) {
        let admin: Address = Self::require_admin(&env);

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
            (Symbol::new(&env, "remove_currency"),),
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
            (Symbol::new(&env, "set_withdraw_currency"),),
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
            (Symbol::new(&env, "set_withdraw_verifier"),),
            (Self::get_admin_internal(&env), verifier_address.clone()),
        );
    }

    fn set_oracle_by_admin(env: Env, oracle: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Oracle, &oracle);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_oracle"),),
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
            (Symbol::new(&env, "set_treasurer"),),
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
            (Symbol::new(&env, "set_minter_manager"),),
            (Self::get_admin_internal(&env), minter_manager),
        );
    }

    fn set_withdraw_fee_ratio_by_admin(env: Env, withdraw_fee_ratio: i128) {
        Self::require_admin(&env);

        // Verify fee ratio
        if withdraw_fee_ratio < 0 || withdraw_fee_ratio > FEE_PRECISION {
            panic_with_error!(&env, VaultError::InvalidWithdrawFeeRatio);
        }

        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeRatio, &withdraw_fee_ratio);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_withdraw_fee_ratio"),),
            (Self::get_admin_internal(&env), withdraw_fee_ratio),
        );
    }

    fn set_withdraw_fee_recv_by_admin(env: Env, withdraw_fee_receiver: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeReceiver, &withdraw_fee_receiver);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_withdraw_fee_receiver"),),
            (Self::get_admin_internal(&env), withdraw_fee_receiver),
        );
    }

    fn set_eip712_domain_by_admin(env: Env, name: String, version: String) {
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
            (Symbol::new(&env, "set_eip712_domain"),),
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
        Self::get_minter_manager_internal(&env)
    }

    fn get_withdraw_fee_ratio(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeRatio)
            .unwrap()
    }

    fn is_initialized(env: Env) -> bool {
        Self::is_initialized_internal(&env)
    }

    fn get_eip712_domain_name(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainName)
            .unwrap_or_else(|| String::from_str(&env, "SolvBTC Vault"))
    }

    fn get_eip712_domain_version(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainVersion)
            .unwrap_or_else(|| String::from_str(&env, "1"))
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
        let type_hash = env.crypto().keccak256(&Bytes::from_slice(env,
            b"Withdraw(uint256 chainId,string action,address user,address withdrawToken,uint256 shares,uint256 nav,bytes32 requestHash)"));
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
        let public_key = BytesN::from_array(env, public_key_bytes);
        let signature = BytesN::from_array(env, signature_bytes);

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

    /// Get minter manager address
    fn get_minter_manager_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::MinterManager)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::MinterManagerNotSet))
    }

    /// Get withdrawal currency
    fn get_withdraw_currency_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawCurrencyNotSet))
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

    /// Mint tokens
    fn mint_tokens(env: &Env, from: &Address, to: &Address, amount: i128) {
        let minter_manager: Address = env
            .storage()
            .instance()
            .get(&DataKey::MinterManager)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::MinterManagerNotSet));

        MinterManagerClient::new(env, &minter_manager).mint(from, to, &amount);
    }

    /// Burn tokens
    fn burn_tokens(env: &Env, from: &Address, amount: i128) {
        let minter_manager: Address = env
            .storage()
            .instance()
            .get(&DataKey::MinterManager)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::MinterManagerNotSet));

        MinterManagerClient::new(env, &minter_manager).burn(from, &amount);
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

    // Calculate mint amount for user after user Deposit
    fn calculate_mint_amount(
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
        let numerator = deposit_amount
            .checked_mul(shares_precision)
            .and_then(|x| x.checked_mul(nav_precision))
            .expect("Overflow in numerator calculation");

        // Denominator: nav * currency_precision
        let denominator = nav
            .checked_mul(currency_precision)
            .expect("Overflow in denominator calculation");

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

    /// Get EIP712 domain name (internal function)
    fn get_eip712_domain_name_internal(env: &Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainName)
            .unwrap_or_else(|| String::from_str(env, "Solv Vault Withdraw"))
    }

    /// Get EIP712 domain version (internal function)
    fn get_eip712_domain_version_internal(env: &Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::EIP712DomainVersion)
            .unwrap_or_else(|| String::from_str(env, "1"))
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
