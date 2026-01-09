use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, xdr::ToXdr, Address,
    Bytes, BytesN, Env, Map, String, Symbol, Vec, crypto::Hash,
};
use stellar_default_impl_macro::default_impl;
use stellar_ownable::{self as ownable, Ownable};
use stellar_ownable_macro::only_owner;
use stellar_upgradeable::UpgradeableInternal;
use stellar_upgradeable_macros::Upgradeable;

// Import dependencies
use crate::dependencies::*;
// Import traits
use crate::traits::*;

// ==================== Constants ====================

/// Maximum number of supported currencies
const MAX_CURRENCIES: u32 = 10;

/// Fee precision (10000 = 100%)
const FEE_PRECISION: i128 = 10000;

/// StrKey address length for Soroban addresses.
const ADDRESS_STRKEY_LENGTH: usize = 56;

/// Ethereum personal_sign V offset.
const ETHEREUM_V_OFFSET: u8 = 27;

// ==================== Data Structures ====================

/// Storage data key enum
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    /// Oracle contract address
    Oracle,
    /// Treasurer address
    Treasurer,
    /// Withdrawal verifier: Secp256k1 uncompressed public key (65 bytes)
    WithdrawVerifier,
    /// Token contract address
    TokenContract,
    /// Supported currencies mapping (Map<Address, bool>)
    AllowedCurrency,
    /// Deposit fee ratio per currency: Map<Address, i128>
    CurrencyDepositFee,
    /// Withdrawal currency
    WithdrawCurrency,
    /// Withdrawal fee ratio
    WithdrawFeeRatio,
    /// Withdraw fee receiver address
    WithdrawFeeReceiver,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracttype]
pub struct Domain {
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
    /// Currency not supported
    CurrencyNotAllowed = 301,
    /// Exceeds maximum currency quantity
    TooManyCurrencies = 302,
    /// Currency already exists
    CurrencyAlreadyExists = 303,
    /// Currency does not exist
    CurrencyNotExists = 304,
    /// Invalid amount
    InvalidAmount = 305,
    /// Invalid NAV
    InvalidNav = 306,
    /// Withdraw fee ratio not set or invalid
    WithdrawFeeRatioNotSet = 307,
    /// Invalid withdraw fee ratio
    InvalidWithdrawFeeRatio = 308,
    /// Request already exists
    RequestAlreadyExists = 309,
    /// Insufficient balance
    InsufficientBalance = 310,
    /// Invalid request status
    InvalidRequestStatus = 311,
    /// Invalid deposit fee ratio
    InvalidDepositFeeRatio = 312,
    /// Insufficient permissions
    Unauthorized = 313,
    /// Invalid signature type
    //InvalidSignatureType = 314, // removed with Ed25519 support
    /// Withdraw verifier not set
    WithdrawVerifierNotSet = 315,
    /// Invalid decimals configuration
    InvalidDecimals = 316,
    /// Invalid verifier key format or length
    InvalidVerifierKey = 317,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracttype]
pub enum WithdrawStatus {
    NotExist = 0,
    Pending = 1,
    Done = 2,
}

/// SolvBTC Vault contract
#[derive(Upgradeable)]
#[contract]
pub struct SolvBTCVault;

// ==================== Constructor ====================

#[contractimpl]
impl SolvBTCVault {
    pub fn __constructor(
        env: &Env,
        admin: Address,
        token_contract: Address,
        oracle: Address,
        treasurer: Address,
        withdraw_verifier: BytesN<65>,
        withdraw_fee_ratio: i128,
        withdraw_fee_receiver: Address,
        withdraw_currency: Address,
    ) {
        // Verify fee ratios
        if withdraw_fee_ratio < 0 || withdraw_fee_ratio > FEE_PRECISION {
            panic_with_error!(env, VaultError::InvalidWithdrawFeeRatio);
        }

        // Early validate decimals configuration to prevent unsafe exponentiation/overflow
        let shares_decimals = TokenClient::new(env, &token_contract).decimals();
        let withdraw_decimals = TokenClient::new(env, &withdraw_currency).decimals();
        let nav_decimals = OracleClient::new(env, &oracle).get_nav_decimals();
        Self::validate_decimals_config(env, shares_decimals, withdraw_decimals, nav_decimals);

        // Set contract owner using OpenZeppelin Ownable
        ownable::set_owner(env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::TokenContract, &token_contract);
        env.storage().instance().set(&DataKey::Oracle, &oracle);
        env.storage()
            .instance()
            .set(&DataKey::Treasurer, &treasurer);
        // Set Secp256k1 verifier (uncompressed 65-byte public key).
        let verifier_bytes = withdraw_verifier.to_array();
        if verifier_bytes[0] != 0x04 {
            panic_with_error!(env, VaultError::InvalidVerifierKey);
        }
        env.storage()
            .instance()
            .set(&DataKey::WithdrawVerifier, &withdraw_verifier);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeRatio, &withdraw_fee_ratio);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeReceiver, &withdraw_fee_receiver);

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

        // Get deposit fee ratio for this currency (can be 0 for no fee)
        let deposit_fee_ratio = Self::get_deposit_fee_ratio_for_currency_internal(&env, &currency);

        // Calculate fee: fee = amount * depositFeeRatio / 10000 (checked arithmetic)
        let fee = amount
            .checked_mul(deposit_fee_ratio)
            .and_then(|x| x.checked_div(FEE_PRECISION))
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount));
        let amount_after_fee = amount
            .checked_sub(fee)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount));

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
        from.require_auth();
        Self::withdraw_request_internal(&env, &from, shares, &request_hash, false);
    }

    fn withdraw_request_with_allowance(env: Env, from: Address, shares: i128, request_hash: Bytes) {
        from.require_auth();
        Self::withdraw_request_internal(&env, &from, shares, &request_hash, true);
    }

    fn withdraw(
        env: Env,
        from: Address,
        shares: i128,
        nav: i128,
        request_hash: Bytes,
        signature: BytesN<65>,
    ) -> i128 {
        from.require_auth(); // Verify caller identity

        // Verify parameters
        if shares <= 0 {
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        if nav <= 0 {
            panic_with_error!(env, VaultError::InvalidNav);
        }

        // Get withdraw token address
        let withdraw_token: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap();

        // Get request key - second hash with all parameters
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

        // Create string message for signing
        let withdraw_message = Self::create_withdraw_string_message(
            &env,
            &from,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
        );

        // Get Secp256k1 verifier public key
        let verifier_public_key: BytesN<65> = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawVerifier)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::WithdrawVerifierNotSet));

        // Recover public key from signature and compare with stored verifier
        let recovered = Self::verify_secp256k1_personal_sign_recover(&env, &signature, &withdraw_message);
        if recovered != verifier_public_key {
            panic_with_error!(env, VaultError::Unauthorized);
        }

        // Get fee ratio
        let withdraw_fee_ratio = Self::get_withdraw_fee_ratio_internal(&env);

        // Calculate amount using shared helper
        let amount = Self::calculate_withdraw_amount(
            &env,
            shares,
            nav,
            Self::get_shares_token_decimals(&env),
            Self::get_withdraw_token_decimals(&env),
            Self::get_nav_decimals_from_oracle(&env),
        );

        // Calculate fee: fee = amount * withdrawFeeRatio / 10000 (checked arithmetic)
        let fee = amount
            .checked_mul(withdraw_fee_ratio)
            .and_then(|x| x.checked_div(FEE_PRECISION))
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount));
        let amount_after_fee = amount
            .checked_sub(fee)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount));

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
            (
                Symbol::new(&env, "withdraw"),
                from.clone(),
                withdraw_token.clone(),
            ),
            WithdrawEvent {
                amount: amount_after_fee,
                fee,
                request_hash,
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
            (
                Symbol::new(&env, "treasurer_deposit"),
                withdraw_currency.clone(),
            ),
            TreasurerDepositEvent { amount },
        );
    }
}

// ==================== Currency management function implementation ====================

#[contractimpl]
impl CurrencyManagement for SolvBTCVault {
    #[only_owner]
    fn add_currency_by_admin(env: Env, currency: Address, deposit_fee_ratio: i128) {
        // Verify deposit fee ratio
        if deposit_fee_ratio < 0 || deposit_fee_ratio > FEE_PRECISION {
            panic_with_error!(env, VaultError::InvalidDepositFeeRatio);
        }

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

        // Validate decimals compatibility with current configuration before adding
        let new_currency_decimals = TokenClient::new(&env, &currency).decimals();
        let shares_decimals = Self::get_shares_token_decimals(&env);
        let nav_decimals = Self::get_nav_decimals_from_oracle(&env);
        Self::validate_decimals_config(&env, shares_decimals, new_currency_decimals, nav_decimals);

        // Add currency
        currencies.set(currency.clone(), true);
        env.storage()
            .instance()
            .set(&DataKey::AllowedCurrency, &currencies);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "add_currency"), currency.clone()),
            SetAllowedCurrencyEvent { allowed: true },
        );

        // Set deposit fee for this currency
        Self::set_deposit_fee_ratio_internal(&env, &currency, deposit_fee_ratio);
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

        // Remove deposit fee for this currency
        let mut deposit_fees: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::CurrencyDepositFee)
            .unwrap_or_else(|| Map::new(&env));
        deposit_fees.remove(currency.clone());
        env.storage()
            .instance()
            .set(&DataKey::CurrencyDepositFee, &deposit_fees);

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

    fn get_shares_token(env: Env) -> Address {
        Self::get_token_contract_internal(&env)
    }
}

// ==================== System management function implementation ====================

#[contractimpl]
impl SystemManagement for SolvBTCVault {
    #[only_owner]
    fn set_withdraw_verifier_by_admin(env: Env, verifier_public_key: BytesN<65>) {
        // Validate Secp256k1 uncompressed public key format: first byte should be 0x04
        let verifier_bytes = verifier_public_key.to_array();
        if verifier_bytes[0] != 0x04 {
            panic_with_error!(env, VaultError::InvalidVerifierKey);
        }

        // Store verifier public key
        env.storage()
            .instance()
            .set(&DataKey::WithdrawVerifier, &verifier_public_key);

        // Publish event
        env.events().publish(
            (
                Symbol::new(&env, "set_withdraw_verifier"),
                verifier_public_key.clone(),
            ),
            Self::get_admin_internal(&env),
        );
    }

    #[only_owner]
    fn set_oracle_by_admin(env: Env, oracle: Address) {
        // Validate decimals compatibility with the new oracle before updating
        let nav_decimals = OracleClient::new(&env, &oracle).get_nav_decimals();
        let shares_decimals = Self::get_shares_token_decimals(&env);
        let withdraw_decimals = Self::get_withdraw_token_decimals(&env);
        Self::validate_decimals_config(&env, shares_decimals, withdraw_decimals, nav_decimals);
        env.storage().instance().set(&DataKey::Oracle, &oracle);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_oracle"), oracle.clone()),
            Self::get_admin_internal(&env),
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
            Self::get_admin_internal(&env),
        );
    }

    #[only_owner]
    fn set_deposit_fee_ratio_by_admin(env: Env, currency: Address, deposit_fee_ratio: i128) {
        // Verify fee ratio
        if deposit_fee_ratio < 0 || deposit_fee_ratio > FEE_PRECISION {
            panic_with_error!(env, VaultError::InvalidDepositFeeRatio);
        }

        // Check if currency is supported
        if !Self::is_currency_supported_internal(&env, &currency) {
            panic_with_error!(env, VaultError::CurrencyNotAllowed);
        }

        // Set deposit fee ratio 
        Self::set_deposit_fee_ratio_internal(&env, &currency, deposit_fee_ratio);
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
            (Self::get_admin_internal(&env), withdraw_fee_ratio),
        );
    }

    #[only_owner]
    fn set_withdraw_fee_recv_by_admin(env: Env, withdraw_fee_receiver: Address) {
        env.storage()
            .instance()
            .set(&DataKey::WithdrawFeeReceiver, &withdraw_fee_receiver);

        // Publish event
        env.events().publish(
            (
                Symbol::new(&env, "set_withdraw_fee_receiver"),
                withdraw_fee_receiver.clone(),
            ),
            Self::get_admin_internal(&env),
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

    fn get_withdraw_verifier(env: Env) -> Option<BytesN<65>> {
        env.storage().instance().get(&DataKey::WithdrawVerifier)
    }

    fn get_oracle(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Oracle).unwrap() // Set in constructor
    }

    fn get_treasurer(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasurer).unwrap() // Set in constructor
    }

    fn get_withdraw_fee_ratio(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeRatio)
            .unwrap_or(0)
    }

    fn get_deposit_fee_ratio(env: Env, currency: Address) -> i128 {
        Self::get_deposit_fee_ratio_for_currency_internal(&env, &currency)
    }


    fn get_withdraw_fee_receiver(env: Env) -> Address {
        Self::get_withdraw_fee_receiver_internal(&env)
    }
}

// ==================== Internal helper functions ====================

impl SolvBTCVault {
    /// Create withdrawal message string for signature verification (EIP191 style)
    pub(crate) fn create_withdraw_string_message(
        env: &Env,
        user: &Address,
        shares: i128,
        withdraw_token: &Address,
        nav: i128,
        request_hash: &Bytes,
    ) -> Bytes {
        let mut message = Bytes::new(env);
        message.append(&Bytes::from_slice(env, b"stellar\n"));

        message.append(&Bytes::from_slice(env, b"withdraw\n"));

        message.append(&Bytes::from_slice(env, b"vault: "));
        let vault_address = env.current_contract_address();
        message.append(&Self::address_to_bytes(env, &vault_address));
        message.append(&Bytes::from_slice(env, b"\n"));
        
        message.append(&Bytes::from_slice(env, b"user: "));
        message.append(&Self::address_to_bytes(env, user));
        message.append(&Bytes::from_slice(env, b"\n"));
        
        message.append(&Bytes::from_slice(env, b"withdraw_token: "));
        message.append(&Self::address_to_bytes(env, withdraw_token));
        message.append(&Bytes::from_slice(env, b"\n"));
        
        message.append(&Bytes::from_slice(env, b"shares: "));
        message.append(&Self::i128_to_ascii_bytes(env, shares));
        message.append(&Bytes::from_slice(env, b"\n"));
        
        message.append(&Bytes::from_slice(env, b"nav: "));
        message.append(&Self::i128_to_ascii_bytes(env, nav));
        message.append(&Bytes::from_slice(env, b"\n"));
        
        message.append(&Bytes::from_slice(env, b"request_hash: "));
        message.append(&Self::bytes_to_hex_string_bytes(env, request_hash));
        
        message
    }

    fn bytes_to_hex_string_bytes(env: &Env, data: &Bytes) -> Bytes {
        let len = data.len() as usize;
        let mut buf = [0u8; 32];
        if len > buf.len() {
            panic_with_error!(env, VaultError::InvalidVerifierKey);
        }
        data.copy_into_slice(&mut buf[..len]);

        let mut hex_buf = [0u8; 64];
        let hex_chars = b"0123456789abcdef";

        for i in 0..len {
            let b = buf[i];
            hex_buf[i * 2] = hex_chars[(b >> 4) as usize];
            hex_buf[i * 2 + 1] = hex_chars[(b & 0x0F) as usize];
        }

        Bytes::from_slice(env, &hex_buf[..len * 2])
    }

    fn u32_to_ascii_bytes(env: &Env, mut n: u32) -> Bytes {
        if n == 0 {
            return Bytes::from_slice(env, b"0");
        }
        let mut buf = [0u8; 10];
        let mut i = 10;
      
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        Bytes::from_slice(env, &buf[i..])
    }

    fn personal_sign_hash(env: &Env, message: &Bytes) -> Hash<32> {
        let mut eth_msg = Bytes::new(env);
        eth_msg.append(&Bytes::from_slice(
            env,
            b"\x19Ethereum Signed Message:\n",
        ));
        eth_msg.append(&Self::u32_to_ascii_bytes(env, message.len()));
        eth_msg.append(message);

        env.crypto().keccak256(&eth_msg)
    }

    /// Recover public key from personal_sign signature
    fn verify_secp256k1_personal_sign_recover(
        env: &Env,
        signature: &BytesN<65>,
        message: &Bytes,
    ) -> BytesN<65> {
        let msg_hash = Self::personal_sign_hash(env, message);

        let sig_array = signature.to_array();
        let mut rs_array = [0u8; 64];
        rs_array.copy_from_slice(&sig_array[0..64]);
        let rs_bytes = BytesN::from_array(env, &rs_array);

        let v_byte = sig_array[64];
        let recovery_id = if v_byte >= ETHEREUM_V_OFFSET {
            (v_byte - ETHEREUM_V_OFFSET) as u32
        } else {
            v_byte as u32
        };

        if recovery_id > 1 {
            panic_with_error!(env, VaultError::Unauthorized);
        }

        env.crypto().secp256k1_recover(&msg_hash, &rs_bytes, recovery_id)
    }

    fn address_to_bytes(env: &Env, s: &Address) -> Bytes {
        let str = s.to_string();
        let len: usize = str.len() as usize;
        let mut tmp = [0u8; ADDRESS_STRKEY_LENGTH];
        if len > tmp.len() {
            panic_with_error!(env, VaultError::InvalidVerifierKey);
        }
        str.copy_into_slice(&mut tmp[..len]);
        Bytes::from_slice(env, &tmp[..len])
    }

    fn i128_to_ascii_bytes(env: &Env, mut n: i128) -> Bytes {
        if n == 0 {
            return Bytes::from_slice(env, b"0");
        }
        let mut buf = [0u8; 40];
        let mut i = 40;
        let is_neg = n < 0;
       
        if is_neg {
            n = -n;
        }

        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }

        if is_neg {
            i -= 1;
            buf[i] = b'-';
        }

        Bytes::from_slice(env, &buf[i..])
    }

    /// Get admin address (internal helper)
    fn get_admin_internal(env: &Env) -> Address {
        ownable::get_owner(env).unwrap()
    }

    /// Get verifier public key

    /// Get treasurer address
    fn get_treasurer_internal(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Treasurer).unwrap() // Set in constructor
    }

    /// Get withdrawal currency
    fn get_withdraw_currency_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawCurrency)
            .unwrap() // Set in constructor, should always exist
    }

    /// Get deposit fee ratio for a specific currency
    fn get_deposit_fee_ratio_for_currency_internal(env: &Env, currency: &Address) -> i128 {
        let deposit_fees: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::CurrencyDepositFee)
            .unwrap_or_else(|| Map::new(env));

        // Return the fee for this currency, or 0 if not set
        deposit_fees.get(currency.clone()).unwrap_or(0)
    }

    /// Set deposit fee ratio for a specific currency (internal helper)
    fn set_deposit_fee_ratio_internal(env: &Env, currency: &Address, deposit_fee_ratio: i128) {
        // Update deposit fee for this currency
        let mut deposit_fees: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::CurrencyDepositFee)
            .unwrap_or_else(|| Map::new(env));
        deposit_fees.set(currency.clone(), deposit_fee_ratio);
        env.storage()
            .instance()
            .set(&DataKey::CurrencyDepositFee, &deposit_fees);

        // Publish event
        env.events().publish(
            (Symbol::new(env, "set_deposit_fee_ratio"), currency.clone()),
            (Self::get_admin_internal(env), deposit_fee_ratio),
        );
    }

    /// Get withdrawal fee ratio
    fn get_withdraw_fee_ratio_internal(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeRatio)
            .unwrap_or(0)
    }

    /// Get withdrawal fee receiver
    fn get_withdraw_fee_receiver_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawFeeReceiver)
            .unwrap() // Set in constructor
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
        let oracle_address: Address = env.storage().instance().get(&DataKey::Oracle).unwrap(); // Set in constructor

        // Call Oracle contract's get_nav method
        OracleClient::new(env, &oracle_address).get_nav()
    }

    /// Get NAV decimals from Oracle contract
    fn get_nav_decimals_from_oracle(env: &Env) -> u32 {
        let oracle_address: Address = env.storage().instance().get(&DataKey::Oracle).unwrap(); // Set in constructor

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

    /// Validate decimals configuration: each ≤ 18 and total ≤ 38
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn validate_decimals_config(env: &Env, decimals_a: u32, decimals_b: u32, decimals_c: u32) {
        if decimals_a > 18 || decimals_b > 18 || decimals_c > 18 {
            panic_with_error!(env, VaultError::InvalidDecimals);
        }
        if (decimals_a + decimals_b + decimals_c) > 38 {
            panic_with_error!(env, VaultError::InvalidDecimals);
        }
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

    // Calculate mint amount for user after user Deposit
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn calculate_mint_amount(
        env: &Env,
        deposit_amount: i128,
        nav: i128,
        currency_decimals: u32,
        shares_decimals: u32,
        nav_decimals: u32,
    ) -> i128 {
        // shares = amount * (10^shares_decimals) * (10^nav_decimals) / (nav * (10^currency_decimals))
        // Validate decimals configuration
        Self::validate_decimals_config(env, shares_decimals, currency_decimals, nav_decimals);

        // Factor out common power-of-10 to reduce intermediate values
        // c = min(shares_decimals, currency_decimals)
        // amount' = amount * 10^(shares_decimals - c) / 10^(currency_decimals - c)
        // shares = amount' * 10^nav_decimals / nav

        // Validate NAV before calculation
        if nav <= 0 {
            panic_with_error!(env, VaultError::InvalidNav);
        }

        let common_factor = shares_decimals.min(currency_decimals);
        let nav_scale = 10_i128.pow(nav_decimals);

        // Step 1: scale amount by 10^(shares_decimals - common_factor) / 10^(currency_decimals - common_factor)
        let scaled_amount = if shares_decimals >= currency_decimals {
            let scale = 10_i128.pow(shares_decimals - common_factor);
            deposit_amount
                .checked_mul(scale)
                .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount))
        } else {
            let scale = 10_i128.pow(currency_decimals - common_factor);
            deposit_amount
                .checked_div(scale)
                .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount))
        };

        // Step 2: multiply by nav_scale and divide by nav (checked)

        let minted = scaled_amount
            .checked_mul(nav_scale)
            .and_then(|x| x.checked_div(nav))
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount));

        minted
    }

    /// Get token contract address
    fn get_token_contract_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap()
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
        let request_key_hash = env.crypto().sha256(&data);
        Bytes::from_array(env, &request_key_hash.to_array())
    }

    /// Calculate withdrawal amount based on shares, nav and decimals
    /// Uses optimized calculation to avoid overflow
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn calculate_withdraw_amount(
        env: &Env,
        shares: i128,
        nav: i128,
        shares_token_decimals: u32,
        withdraw_token_decimals: u32,
        nav_decimals: u32,
    ) -> i128 {
        // Validate decimals configuration
        Self::validate_decimals_config(
            env,
            shares_token_decimals,
            withdraw_token_decimals,
            nav_decimals,
        );

        // Validate NAV before calculation
        if nav <= 0 {
            panic_with_error!(env, VaultError::InvalidNav);
        }

        // Optimize calculation by extracting common factor to reduce intermediate values
        // Formula: amount = (shares * nav * 10^withdraw_decimals) / (10^nav_decimals * 10^shares_decimals)
        // Optimized: reduce common factors first

        let common_factor = shares_token_decimals.min(withdraw_token_decimals);
        let nav_scale = 10_i128.pow(nav_decimals);

        // Step 1: Scale shares by 10^(withdraw_decimals - common_factor) / 10^(shares_decimals - common_factor)
        let scaled_shares = if withdraw_token_decimals >= shares_token_decimals {
            let scale = 10_i128.pow(withdraw_token_decimals - common_factor);
            shares
                .checked_mul(scale)
                .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount))
        } else {
            let scale = 10_i128.pow(shares_token_decimals - common_factor);
            shares
                .checked_div(scale)
                .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount))
        };

        // Step 2: Multiply by nav and divide by nav_scale
        let amount = scaled_shares
            .checked_mul(nav)
            .and_then(|x| x.checked_div(nav_scale))
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidAmount));

        amount
    }

    /// Internal function to handle withdraw request logic
    fn withdraw_request_internal(
        env: &Env,
        from: &Address,
        shares: i128,
        request_hash: &Bytes,
        use_burn_from: bool,
    ) {
        // Verify parameters
        if shares <= 0 {
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        // Get current nav from oracle
        let current_nav = Self::get_nav_from_oracle(env);

        // Get withdraw token address (first supported currency)
        let withdraw_token: Address = Self::get_withdraw_currency_internal(env);

        // Generate unique request key: second hash with all parameters (_msgSender, withdrawToken, requestHash, shares, nav)
        let request_key = Self::generate_request_key(
            env,
            from,
            &withdraw_token,
            request_hash,
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
        let token_client = TokenClient::new(env, &token_contract);
        let user_balance = token_client.balance(from);

        if user_balance < shares {
            panic_with_error!(env, VaultError::InsufficientBalance);
        }

        // Burn user's shares using the appropriate method
        if use_burn_from {
            // Use burn_from with allowance (vault as spender)
            token_client.burn_from(&env.current_contract_address(), from, &shares);
        } else {
            // Use direct burn (requires caller to be the token owner)
            token_client.burn(from, &shares);
        }

        // Set withdraw request status to PENDING
        env.storage()
            .persistent()
            .set(&request_key, &WithdrawStatus::Pending);

        // Calculate preview amount for the event using the same formula as withdraw
        let preview_amount = Self::calculate_withdraw_amount(
            env,
            shares,
            current_nav,
            Self::get_shares_token_decimals(env),
            Self::get_withdraw_token_decimals(env),
            Self::get_nav_decimals_from_oracle(env),
        );

        env.events().publish(
            ( Symbol::new(env, "withdraw_request"), from.clone(), withdraw_token.clone()),
            WithdrawRequestEvent {
                token_contract,
                shares,
                request_hash: request_hash.clone(),
                nav: current_nav,
                amount: preview_amount,
            },
        );
    }
}

// ==================== Ownable Implementation ====================

#[default_impl]
#[contractimpl]
impl Ownable for SolvBTCVault {}

// Provide upgrade auth via OpenZeppelin UpgradeableInternal
impl UpgradeableInternal for SolvBTCVault {
    fn _require_auth(e: &Env, operator: &Address) {
        operator.require_auth();
        let owner = ownable::get_owner(e).unwrap();
        if *operator != owner {
            panic_with_error!(e, VaultError::Unauthorized);
        }
    }
}
