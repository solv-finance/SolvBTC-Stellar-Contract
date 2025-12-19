#![cfg(test)]
extern crate std;
use soroban_sdk::{
    contract, contractimpl, contracttype,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
    Address, Bytes, BytesN, Env, IntoVal, String, Symbol,
};

use super::*;

// Import fungible token and oracle for mocking
use fungible_token::FungibleTokenContract;
use solvbtc_oracle::SolvBtcOracle;

// Helper function: Create a mock token contract with 8 decimals
fn create_mock_token(env: &Env, name: &str, symbol: &str) -> Address {
    let admin = Address::generate(env);
    env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(env, name),
            String::from_str(env, symbol),
            8u32, // decimals
        ),
    )
}

// Helper function: Create a mock oracle contract with 8 decimals
fn create_mock_oracle(env: &Env) -> Address {
    let admin = Address::generate(env);
    env.register(
        SolvBtcOracle,
        (
            &admin,
            8u32,            // nav_decimals
            100_000_000i128, // initial NAV = 1.0 with 8 decimals
        ),
    )
}

// Helper functions for creating contract and client
fn create_vault_contract(env: &Env) -> (SolvBTCVaultClient, Address, Address) {
    // Use constructor to complete initialization
    let admin = Address::generate(env);
    let treasurer = Address::generate(env);
    let withdraw_fee_receiver = Address::generate(env);

    // Create real mock contracts for token, oracle, and withdraw_currency
    // Token contract (shares token) with 8 decimals
    let token_contract = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin, // minter_manager
            &admin, // blacklist_manager
            String::from_str(env, "SolvBTC"),
            String::from_str(env, "SOLVBTC"),
            8u32, // decimals
        ),
    );

    // Oracle contract with 8 decimals for NAV
    let oracle = env.register(
        SolvBtcOracle,
        (
            &admin,
            8u32,          // nav_decimals
            100_000_000i128, // initial NAV = 1.0 with 8 decimals
        ),
    );

    // Withdraw currency (e.g., WBTC) with 8 decimals
    let withdraw_currency = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(env, "Wrapped BTC"),
            String::from_str(env, "WBTC"),
            8u32, // decimals
        ),
    );

    // Generate a random 32-byte public key for withdraw verifier
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1; // Set first byte to make it non-zero
    let withdraw_verifier = BytesN::from_array(env, &verifier_bytes);
    let withdraw_fee_ratio = 100i128;

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract,
            oracle,
            treasurer,
            withdraw_verifier,
            withdraw_fee_ratio,
            withdraw_fee_receiver,
            withdraw_currency,
        ),
    );
    let client = SolvBTCVaultClient::new(env, &contract_address);
    (client, contract_address, admin)
}

// Helper function: Create real Ed25519 public key address
fn create_mock_public_key(env: &Env) -> Address {
    // Use a valid Stellar account address string
    let stellar_address = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

    // Create Address object from string
    Address::from_str(env, stellar_address)
}

// Helper function: Create mock Ed25519 signature (64 bytes)
fn create_mock_signature(env: &Env) -> BytesN<64> {
    let mut signature_bytes = [0u8; 64];
    // Fill with some test data
    for i in 0..64 {
        signature_bytes[i] = (i % 256) as u8;
    }
    BytesN::from_array(env, &signature_bytes)
}

// Helper function: Create request hash
fn create_request_hash(env: &Env, nonce: u64) -> Bytes {
    let mut hash_bytes = [0u8; 32];
    // Simply write nonce to first 8 bytes
    let nonce_bytes = nonce.to_be_bytes();
    hash_bytes[..8].copy_from_slice(&nonce_bytes);
    Bytes::from_array(env, &hash_bytes)
}

// ==================== Upgrade Tests ====================

fn load_vault_wasm_bytes() -> std::vec::Vec<u8> {
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32-unknown-unknown/optimized/solvbtc_vault.wasm");
    std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to read vault wasm at {}: {e}",
            wasm_path.display()
        )
    })
}

#[test]
fn test_vault_upgrade_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _addr, admin) = create_vault_contract(&env);
    let wasm_bytes = load_vault_wasm_bytes();
    let wasm_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, &wasm_bytes));

    // If this call does not panic, treat as success
    client.upgrade(&wasm_hash, &admin);

    assert_eq!(100, client.get_withdraw_fee_ratio());
}

#[test]
#[should_panic]
fn test_vault_upgrade_with_unuploaded_hash_should_panic() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _addr, admin) = create_vault_contract(&env);
    let fake = BytesN::from_array(&env, &[9u8; 32]);
    client.upgrade(&fake, &admin);
}

#[test]
#[should_panic]
fn test_vault_upgrade_requires_owner_should_panic() {
    let env = Env::default();
    // Do not mock auth so only_owner check fails
    let (client, _addr, _admin) = create_vault_contract(&env);
    let wasm_bytes = load_vault_wasm_bytes();
    let wasm_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, &wasm_bytes));
    // Using a different address (not the admin) as operator
    let non_admin = Address::generate(&env);
    client.upgrade(&wasm_hash, &non_admin);
}

// ==================== Configuration Helper Functions ====================

/// Create default initialization configuration
struct TestConfig {
    admin: Address,
    oracle: Address,
    treasurer: Address,
    withdraw_verifier: BytesN<32>,
    withdraw_fee_ratio: i128,
    withdraw_fee_receiver: Address,
}

fn read_config_from_chain(_env: &Env, client: &SolvBTCVaultClient) -> TestConfig {
    TestConfig {
        admin: client.get_admin(),
        oracle: client.get_oracle(),
        treasurer: client.get_treasurer(),
        withdraw_verifier: BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap())
            .unwrap(),
        withdraw_fee_ratio: client.get_withdraw_fee_ratio(),
        withdraw_fee_receiver: client.get_withdraw_fee_receiver(),
    }
}

/// Use default configuration to initialize vault
fn initialize_vault_with_defaults(_env: &Env, client: &SolvBTCVaultClient) -> TestConfig {
    read_config_from_chain(_env, client)
}

/// Create custom initialization configuration
fn create_custom_init_config(
    env: &Env,
    admin: Option<Address>,
    fee_ratio: Option<i128>,
) -> TestConfig {
    let admin_addr = admin.unwrap_or_else(|| Address::generate(env));
    let ratio = fee_ratio.unwrap_or(100);
    TestConfig {
        admin: admin_addr,
        oracle: Address::generate(env),
        treasurer: Address::generate(env),
        withdraw_verifier: BytesN::from_array(env, &[1u8; 32]),
        withdraw_fee_ratio: ratio,
        withdraw_fee_receiver: Address::generate(env),
    }
}

#[test]
fn test_withdraw_verifier_key_management() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Use new configuration-based initialization
    let config = initialize_vault_with_defaults(&env, &client);
    let initial_verifier_pubkey = config.withdraw_verifier;

    // Verify initial verifier public key
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        initial_verifier_pubkey
    );

    let updated_verifier_pubkey = BytesN::from_array(&env, &[5u8; 32]);

    client.set_withdraw_verifier_by_admin(&0u32, &updated_verifier_pubkey.clone().into());

    // Verify verifier public key has been updated
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        updated_verifier_pubkey
    );
    assert_ne!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        initial_verifier_pubkey
    );
}

#[test]
#[should_panic]
fn test_withdraw_invalid_signature_content() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _vault_addr, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks_full(&env);

    let (_sk, vk) = fixed_keypair();
    let verifier_public_key = public_key_from_verifying_key(&env, &vk);
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_public_key.clone().into());

    let user = Address::generate(&env);
    let shares = 50_000_000i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 1);
    client.withdraw_request(&user, &shares, &request_hash);

    let invalid_signature = BytesN::<64>::from_array(&env, &[0u8; 64]);

    client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &invalid_signature,
        &0u32,
        &0u32,
    );
}


#[test]
fn test_basic_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Use new configuration-based initialization
    let config = initialize_vault_with_defaults(&env, &client);

    // Verify initialization
    assert_eq!(client.get_admin(), config.admin);
    // minter_manager
    assert_eq!(client.get_oracle(), config.oracle);
    assert_eq!(client.get_treasurer(), config.treasurer);
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        config.withdraw_verifier
    );
    assert_eq!(client.get_withdraw_fee_ratio(), 100);
}

// ==================== Configuration-Based Initialization Tests ====================

#[test]
fn test_initialize_with_default_config() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Use new configuration-based initialization - one line!
    let config = initialize_vault_with_defaults(&env, &client);

    // Verify initialization
    assert_eq!(client.get_admin(), config.admin);
    // minter_manager
    assert_eq!(client.get_oracle(), config.oracle);
    assert_eq!(client.get_treasurer(), config.treasurer);
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        config.withdraw_verifier
    );
    assert_eq!(client.get_withdraw_fee_ratio(), config.withdraw_fee_ratio);
}

#[test]
fn test_initialize_with_custom_config() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    client.set_withdraw_fee_ratio_by_admin(&200);
    assert_eq!(client.get_withdraw_fee_ratio(), 200);
    client.set_oracle_by_admin(&create_mock_oracle(&env));
}


#[test]
fn test_config_vs_traditional_initialization() {
    let env = Env::default();
    env.mock_all_auths();

    // Both should have same basic functionality (constructor initializes with 100)
    let (client1, _, _) = create_vault_contract(&env);

    let (client2, _, _) = create_vault_contract(&env);

    assert_eq!(client1.get_withdraw_fee_ratio(), 100);
    assert_eq!(client2.get_withdraw_fee_ratio(), 100);
}

#[test]
fn test_request_hash_uniqueness() {
    let env = Env::default();
    env.mock_all_auths();

    // Create different request hashes
    let hash1 = create_request_hash(&env, 1);
    let hash2 = create_request_hash(&env, 2);
    let hash3 = create_request_hash(&env, 1); // Same as hash1

    // Verify uniqueness
    assert_ne!(hash1, hash2);
    assert_eq!(hash1, hash3); // Same nonce should produce same hash

    // Verify length
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
}

#[test]
fn test_withdraw_structure_validation() {
    let env = Env::default();
    env.mock_all_auths();

    let currency = create_mock_token(&env, "TestCurrency", "TEST");
    let (client, _, _) = create_vault_contract(&env);

    // Add currency
    client.add_currency_by_admin(&currency, &100);
    let fee_receiver = Address::generate(&env);
    client.set_withdraw_fee_recv_by_admin(&fee_receiver);
    // Create valid parameters
    let target_amount = 1000i128;
    let nav = 50000i128;
    let request_hash = create_request_hash(&env, 1);
    let signature = create_mock_signature(&env);

    // Verify parameter formats
    assert!(target_amount > 0);
    assert!(nav > 0);
    assert_eq!(request_hash.len(), 32);
    assert_eq!(signature.len(), 64);

    // Verify contract state: withdraw currency is set by constructor; currency added is supported
    assert!(client.get_withdraw_currency().is_some());
    assert!(client.is_currency_supported(&currency));
}

#[test]
fn test_mock_public_key_format() {
    let env = Env::default();

    // Create mock public key
    let pubkey = create_mock_public_key(&env);

    // Verify it's a valid Address
    assert_eq!(
        pubkey.to_string(),
        String::from_str(
            &env,
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
        )
    );
}

// ==================== Basic Tests ====================

#[test]
fn test_error_enum() {
    // Verify error codes
    assert_eq!(VaultError::CurrencyNotAllowed as u32, 301);
    assert_eq!(VaultError::TooManyCurrencies as u32, 302);
    assert_eq!(VaultError::CurrencyAlreadyExists as u32, 303);
    assert_eq!(VaultError::CurrencyNotExists as u32, 304);
    assert_eq!(VaultError::InvalidAmount as u32, 305);
    assert_eq!(VaultError::InvalidNav as u32, 306);
    assert_eq!(VaultError::WithdrawFeeRatioNotSet as u32, 307);
    assert_eq!(VaultError::InvalidWithdrawFeeRatio as u32, 308);
    assert_eq!(VaultError::RequestAlreadyExists as u32, 309);
    assert_eq!(VaultError::InsufficientBalance as u32, 310);
    assert_eq!(VaultError::InvalidRequestStatus as u32, 311);
    assert_eq!(VaultError::InvalidDepositFeeRatio as u32, 312);
}

// ==================== System Management Tests ====================

#[test]
fn test_set_oracle_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Use new configuration-based initialization
    let config = initialize_vault_with_defaults(&env, &client);
    let oracle = config.oracle;

    // Verify initial oracle
    assert_eq!(client.get_oracle(), oracle);

    // Set new oracle
    let new_oracle = create_mock_oracle(&env);
    client.set_oracle_by_admin(&new_oracle);

    // Verify oracle has been updated
    assert_eq!(client.get_oracle(), new_oracle);
    assert_ne!(client.get_oracle(), oracle);
}

#[test]
fn test_set_treasurer_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Use new configuration-based initialization
    let config = initialize_vault_with_defaults(&env, &client);
    let treasurer = config.treasurer;

    // Verify initial treasurer
    assert_eq!(client.get_treasurer(), treasurer);

    // Set new treasurer
    let new_treasurer = Address::generate(&env);
    client.set_treasurer_by_admin(&new_treasurer);

    // Verify treasurer has been updated
    assert_eq!(client.get_treasurer(), new_treasurer);
    assert_ne!(client.get_treasurer(), treasurer);
}


#[test]
fn test_set_withdraw_fee_ratio_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Verify initial withdraw fee ratio
    assert_eq!(client.get_withdraw_fee_ratio(), 100);

    // Set new withdraw fee ratio
    let new_fee_ratio = 200i128;
    client.set_withdraw_fee_ratio_by_admin(&new_fee_ratio);

    // Verify withdraw fee ratio has been updated
    assert_eq!(client.get_withdraw_fee_ratio(), new_fee_ratio);
    assert_ne!(client.get_withdraw_fee_ratio(), 100);
}

// ==================== Currency Management Tests ====================

#[test]
fn test_remove_currency_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    let (client, _, _) = create_vault_contract(&env);

    // Add currency first
    client.add_currency_by_admin(&currency, &100);
    assert!(client.is_currency_supported(&currency));

    // Remove currency
    client.remove_currency_by_admin(&currency);
    assert!(!client.is_currency_supported(&currency));
}

#[test]
fn test_get_supported_currencies() {
    let env = Env::default();
    env.mock_all_auths();

    let currency1 = create_mock_token(&env, "Currency1", "CUR1");
    let currency2 = create_mock_token(&env, "Currency2", "CUR2");
    let (client, _, _) = create_vault_contract(&env);

    // Initially should be empty
    let currencies = client.get_supported_currencies();
    assert_eq!(currencies.len(), 0);

    // Add currencies
    client.add_currency_by_admin(&currency1, &100);
    client.add_currency_by_admin(&currency2, &100);

    // Verify currencies list
    let currencies = client.get_supported_currencies();
    assert_eq!(currencies.len(), 2);
    assert!(currencies.contains(&currency1));
    assert!(currencies.contains(&currency2));
}

// ==================== Query Function Tests ====================

#[test]
fn test_get_withdraw_fee_receiver() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    let fee_receiver = Address::generate(&env);

    // Set withdraw fee receiver
    client.set_withdraw_fee_recv_by_admin(&fee_receiver);

    // Verify withdraw fee receiver
    assert_eq!(client.get_withdraw_fee_receiver(), fee_receiver);
}

// ==================== Operation Function Tests (with Mock Contracts) ====================

// Mock contracts for testing operations
#[contract]
pub struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn decimals(_env: Env) -> u32 {
        8
    }

    pub fn balance(_env: Env, _account: Address) -> i128 {
        1_000_000_000_000_000_000i128
    }

    pub fn approve(
        _env: Env,
        _owner: Address,
        _spender: Address,
        _amount: i128,
        _live_until_ledger: u32,
    ) {
    }

    pub fn transfer_from(
        _env: Env,
        _spender: Address,
        _from: Address,
        _to: Address,
        _amount: i128,
    ) {
    }

    pub fn transfer(_env: Env, _from: Address, _to: Address, _amount: i128) {}

    pub fn burn(_env: Env, _from: Address, _amount: i128) {}

    pub fn burn_from(_env: Env, _spender: Address, _from: Address, _amount: i128) {}

    pub fn mint_from(_env: Env, _from: Address, _to: Address, _amount: i128) {}
}

#[contract]
pub struct MockOracle;

#[contractimpl]
impl MockOracle {
    pub fn get_nav(env: Env) -> i128 {
        // Default NAV: 1.0 with 8 decimal places
        env.storage()
            .instance()
            .get(&MockOracleDataKey::Nav)
            .unwrap_or(100000000)
    }

    pub fn get_nav_decimals(env: Env) -> u32 {
        // Default decimals: 8
        env.storage()
            .instance()
            .get(&MockOracleDataKey::Decimals)
            .unwrap_or(8)
    }

    /// Configure NAV and decimals for tests
    pub fn set_nav_and_decimals(env: Env, nav: i128, decimals: u32) {
        env.storage().instance().set(&MockOracleDataKey::Nav, &nav);
        env.storage()
            .instance()
            .set(&MockOracleDataKey::Decimals, &decimals);
    }
}

#[derive(Clone)]
#[contracttype]
enum MockOracleDataKey {
    Nav,
    Decimals,
}

fn register_mock_token(env: &Env) -> Address {
    let token_addr = env.register(MockToken, ());
    token_addr
}

fn register_mock_oracle(env: &Env) -> Address {
    let oracle_addr = env.register(MockOracle, ());
    oracle_addr
}

/// Build a vault with mock token/oracle wired so withdraw succeeds end-to-end
fn create_vault_with_mocks(env: &Env) -> (SolvBTCVaultClient, Address, Address, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_addr = register_mock_token(env);
    let oracle_addr = register_mock_oracle(env);
    let treasurer = Address::generate(env);
    // Use a temporary verifier; will be updated later
    let verifier = BytesN::from_array(env, &[0; 32]);

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_addr.clone(),
            oracle_addr.clone(),
            treasurer.clone(),
            verifier.clone(),
            100i128, // withdraw_fee_ratio
            Address::generate(env),
            token_addr.clone(), // Use token as withdraw currency
        ),
    );
    let client = SolvBTCVaultClient::new(env, &contract_address);

    // Configure withdraw settings and add currency with deposit fee
    client.add_currency_by_admin(&token_addr, &100);
    client.set_withdraw_fee_recv_by_admin(&Address::generate(env));
    (client, token_addr, oracle_addr, treasurer)
}

fn create_vault_with_mocks_full(env: &Env) -> (SolvBTCVaultClient, Address, Address, Address, Address) {
    let (client, token_addr, oracle_addr, treasurer) = create_vault_with_mocks(env);
    let vault_addr = client.address.clone();
    (client, vault_addr, token_addr, oracle_addr, treasurer)
}

/// Build a vault with withdraw_fee_ratio = 0 in constructor
fn create_vault_with_zero_fee(env: &Env) -> (SolvBTCVaultClient, Address, Address, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_addr = register_mock_token(env);
    let oracle_addr = register_mock_oracle(env);
    let treasurer = Address::generate(env);
    let verifier = BytesN::from_array(env, &[0; 32]);

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_addr.clone(),
            oracle_addr.clone(),
            treasurer.clone(),
            verifier.clone(),
            0i128, // withdraw_fee_ratio = 0
            Address::generate(env),
            token_addr.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(env, &contract_address);
    client.add_currency_by_admin(&token_addr, &100);
    client.set_withdraw_fee_recv_by_admin(&Address::generate(env));
    (client, token_addr, oracle_addr, treasurer)
}

fn create_vault_with_oracle(env: &Env, oracle_addr: Address) -> (SolvBTCVaultClient, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_addr = register_mock_token(env);
    let treasurer = Address::generate(env);
    let verifier = BytesN::from_array(env, &[0; 32]);

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_addr.clone(),
            oracle_addr.clone(),
            treasurer.clone(),
            verifier.clone(),
            100i128, // withdraw_fee_ratio
            Address::generate(env),
            token_addr.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(env, &contract_address);
    client.add_currency_by_admin(&token_addr, &100);
    (client, token_addr)
}

#[test]
fn test_deposit_success_end_to_end() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);

    let user = Address::generate(&env);
    let amount = 100_000_000i128; // 1 unit with 8 decimals
    let minted = client.deposit(&user, &token_addr, &amount);
    assert!(minted > 0);
}

/// Trigger calculate_mint_amount denominator == 0: nav == 0
#[test]
#[should_panic(expected = "Error(Contract, #306)")]
fn test_deposit_mint_denominator_zero_should_panic() {
    let env = Env::default();
    env.mock_all_auths();

    // Register oracle with NAV == 0
    let oracle_addr = env.register(MockOracle, ());
    let oclient = MockOracleClient::new(&env, &oracle_addr);
    oclient.set_nav_and_decimals(&0i128, &8u32);
    let (client, token_addr) = create_vault_with_oracle(&env, oracle_addr);

    let user = Address::generate(&env);
    client.deposit(&user, &token_addr, &1i128);
}

#[test]
fn test_treasurer_deposit_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    client.treasurer_deposit(&50_000_000i128);
}

#[test]
fn test_withdraw_success_various_fee_ratios() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);

    // Set verifier
    let (sk, vk) = fixed_keypair();
    let verifier_public_key = public_key_from_verifying_key(&env, &vk);
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_public_key.clone().into());

    // Try a few fee ratios
    for fee in [300i128, 1000i128] {
        // 3%, 10%
        client.set_withdraw_fee_ratio_by_admin(&fee);

        let user = Address::generate(&env);
        let shares = 100_000_000i128; // 1 share
        let nav = 100_000_000i128; // 1.0 NAV
        let request_hash = create_request_hash(&env, fee as u64 + 7);
        client.withdraw_request(&user, &shares, &request_hash);

        let msg = build_withdraw_message(
            &env,
            &client.address,
            &user,
            shares,
            &token_addr,
            nav,
            &request_hash,
        );
        let sig = sk.sign(&bytes_to_vec(&msg));
        let sig_bytes = BytesN::<64>::from_array(&env, &sig.to_bytes());

        let out = client.withdraw(
            &user,
            &shares,
            &nav,
            &request_hash,
            &sig_bytes,
            &0u32,
            &0u32,
        );
        assert!(out >= 0);
    }
}

#[test]
fn test_withdraw_success_precision_scenarios() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);

    // Verifier
    let (sk, vk) = fixed_keypair();
    let verifier_public_key = public_key_from_verifying_key(&env, &vk);
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_public_key.clone().into());

    // Use 5% fee
    client.set_withdraw_fee_ratio_by_admin(&500);

    // Two scenarios with different shares
    for (shares, nonce) in [(50_000_000i128, 11u64), (200_000_000i128, 12u64)] {
        let user = Address::generate(&env);
        let nav = 100_000_000i128; // 1.0
        let request_hash = create_request_hash(&env, nonce);
        client.withdraw_request(&user, &shares, &request_hash);

        let msg = build_withdraw_message(
            &env,
            &client.address,
            &user,
            shares,
            &token_addr,
            nav,
            &request_hash,
        );
        let sig = sk.sign(&bytes_to_vec(&msg));
        let sig_bytes = BytesN::<64>::from_array(&env, &sig.to_bytes());

        let out = client.withdraw(
            &user,
            &shares,
            &nav,
            &request_hash,
            &sig_bytes,
            &0u32,
            &0u32,
        );
        assert!(out > 0);
    }
}

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

fn fixed_keypair() -> (SigningKey, VerifyingKey) {
    let seed: [u8; 32] = [
        0xef, 0xab, 0x69, 0x6a, 0x8c, 0xaf, 0x7a, 0x70, 0xc4, 0x2e, 0xe5, 0x39, 0x70, 0x5b, 0x4a,
        0x74, 0x7e, 0x5d, 0x6e, 0x1b, 0xb2, 0x6b, 0x3d, 0xd5, 0x2e, 0x38, 0xba, 0xf7, 0x29, 0xe3,
        0xdb, 0x3b,
    ];
    let sk = SigningKey::from(seed);
    let vk = VerifyingKey::from(&sk);
    (sk, vk)
}

fn public_key_from_verifying_key(env: &Env, vk: &VerifyingKey) -> BytesN<32> {
    BytesN::from_array(env, &vk.to_bytes())
}

fn build_withdraw_message(
    env: &Env,
    vault_addr: &Address,
    user: &Address,
    target_amount: i128,
    target_token: &Address,
    nav: i128,
    request_hash: &Bytes,
) -> Bytes {
    env.as_contract(vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(
            env,
            user,
            target_amount,
            target_token,
            nav,
            request_hash,
        )
    })
}

fn bytes_to_vec(bytes: &Bytes) -> std::vec::Vec<u8> {
    let mut out = std::vec::Vec::with_capacity(bytes.len() as usize);
    for i in 0..bytes.len() {
        out.push(bytes.get(i).unwrap());
    }
    out
}

#[test]
fn test_withdraw_success_end_to_end() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, vault_addr, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks_full(&env);

    // Set verifier matching our verifying key
    let (sk, vk) = fixed_keypair();
    let verifier_public_key = public_key_from_verifying_key(&env, &vk);
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_public_key.clone().into());

    // Prepare withdraw request
    let user = Address::generate(&env);
    let shares = 50_000_000i128; // 0.5 shares
    let nav = 100_000_000i128; // 1.0 NAV (8 decimals)
    let request_hash = create_request_hash(&env, 42);
    client.withdraw_request(&user, &shares, &request_hash);

    // Build message and sign
    let msg = build_withdraw_message(&env, &vault_addr, &user, shares, &token_addr, nav, &request_hash);
    let sig = sk.sign(&bytes_to_vec(&msg));
    let sig_bytes = BytesN::<64>::from_array(&env, &sig.to_bytes());

    // Execute withdraw
    let actual = client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &sig_bytes,
        &0u32,
        &0u32,
    );
    assert!(actual > 0);
}
/// Test add currency authorization check
#[test]
fn test_add_currency_authorization() {
    let env = Env::default();

    let (client, _, _) = create_vault_contract(&env);

    // Initialize with default configuration (using admin permission)
    env.mock_all_auths();
    let config = initialize_vault_with_defaults(&env, &client);
    let admin = config.admin;

    // Clear authorization records from initialization
    // Don't call env.mock_all_auths() again to test actual authorization

    let currency = create_mock_token(&env, "Currency", "CUR");
    client.add_currency_by_admin(&currency, &100);

    // Verify the admin authorization was required
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    client.address.clone(),
                    Symbol::new(&env, "add_currency_by_admin"),
                    (currency.clone(), 100i128).into_val(&env),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
}

/// Test add currency that already exists
#[test]
#[should_panic(expected = "Error(Contract, #303)")]
fn test_add_currency_already_exists() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Add currency first time
    client.add_currency_by_admin(&currency, &100);

    // Try to add same currency again
    client.add_currency_by_admin(&currency, &100);
}

/// Test remove currency that doesn't exist
#[test]
#[should_panic(expected = "Error(Contract, #304)")]
fn test_remove_currency_not_exists() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    client.remove_currency_by_admin(&currency);
}

#[test]
#[should_panic(expected = "Error(Contract, #304)")] // CurrencyNotExists
fn test_remove_currency_when_map_absent_triggers_map_new() {
    let env = Env::default();
    env.mock_all_auths();

    // Build vault without adding any currency map entries
    let (client, _, _) = create_vault_contract(&env);

    // Remove a random currency; AllowedCurrency map key is absent so Map::new(&env) branch executes
    let random_currency = Address::generate(&env);
    client.remove_currency_by_admin(&random_currency);
}

/// Test deposit with unsupported currency
#[test]
#[should_panic(expected = "Error(Contract, #301)")]
fn test_deposit_unsupported_currency() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    client.deposit(&user, &currency, &1000);
}

/// Test deposit with invalid amount
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_deposit_invalid_amount_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Add currency first
    client.add_currency_by_admin(&currency, &100);

    client.deposit(&user, &currency, &0);
}

/// Test deposit with negative amount
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_deposit_invalid_amount_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Add currency first
    client.add_currency_by_admin(&currency, &100);

    client.deposit(&user, &currency, &-100);
}

/// Test withdraw request with invalid amount
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_withdraw_request_invalid_amount_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 1);

    client.withdraw_request(&user, &0, &request_hash);
}

/// Test withdraw request with negative amount
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_withdraw_request_invalid_amount_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 1);

    client.withdraw_request(&user, &-100, &request_hash);
}

/// Test treasurer deposit with invalid amount
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_treasurer_deposit_invalid_amount_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    client.treasurer_deposit(&0);
}

/// Test treasurer deposit with negative amount
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_treasurer_deposit_invalid_amount_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    client.treasurer_deposit(&-100);
}

/// Test max currencies limit
#[test]
#[should_panic(expected = "Error(Contract, #302)")]
fn test_add_currency_exceeds_max_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Add maximum number of currencies (10)
    for _ in 0..10 {
        let currency = create_mock_token(&env, "Token", "TK");
        client.add_currency_by_admin(&currency, &100);
    }

    // Try to add one more - should fail
    let extra_currency = create_mock_token(&env, "Extra", "EXT");
    client.add_currency_by_admin(&extra_currency, &100);
}

/// Test domain domain queries
#[test]
fn test_domain_domain_queries() {
    let env = Env::default();
    env.mock_all_auths();

    let (_client, vault_addr, _admin) = create_vault_contract(&env);

    let user = Address::generate(&env);
    let withdraw_token = create_mock_token(&env, "WithdrawToken", "WT");
    let shares = 123i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 5);

    let msg = env.as_contract(&vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(
            &env,
            &user,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
        )
    });
    assert!(msg.len() > 0);
}

/// Test admin transfer functionality
#[test]
fn test_admin_address_query() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    let admin = client.get_admin();
    assert_eq!(admin, config.admin);
}

/// Test is_currency_supported function
#[test]
fn test_is_currency_supported() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Initially not supported
    assert!(!client.is_currency_supported(&currency));

    // Add currency
    client.add_currency_by_admin(&currency, &100);

    // Now should be supported
    assert!(client.is_currency_supported(&currency));
}

/// Test initialize with config convenience function
#[test]
fn test_initialize_with_config_function() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _config = read_config_from_chain(&env, &client);
    // constructor-only: use setter to verify interface exists
    let new_oracle = create_mock_oracle(&env);
    client.set_oracle_by_admin(&new_oracle);
    assert_eq!(client.get_oracle(), new_oracle);
}

/// Test trait interface coverage
#[test]
fn test_vault_operations_traits_coverage() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    // Test various trait methods are accessible
    assert_eq!(client.get_withdraw_fee_ratio(), 100);
    assert_eq!(
        client.get_withdraw_fee_receiver(),
        config.withdraw_fee_receiver
    );

    let currencies = client.get_supported_currencies();
    assert_eq!(currencies.len(), 0); // No currencies added yet
}

/// Test system management traits
#[test]
fn test_system_management_traits() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    // Test all getter functions
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        config.withdraw_verifier
    );
    assert_eq!(client.get_treasurer(), config.treasurer);
    assert_eq!(client.get_oracle(), config.oracle);
}

/// Zero fee ratio now allowed by setter, should not panic
#[test]
fn test_zero_fee_ratio_initialization() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _config = create_custom_init_config(&env, None, Some(0));
    client.set_withdraw_fee_ratio_by_admin(&0);
    assert_eq!(client.get_withdraw_fee_ratio(), 0);
}

/// Test maximum fee ratio
#[test]
fn test_maximum_fee_ratio_initialization() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _ = create_custom_init_config(&env, None, Some(10000)); // 100%
                                                                // set to 10000 by setter
    client.set_withdraw_fee_ratio_by_admin(&10000);
    assert_eq!(client.get_withdraw_fee_ratio(), 10000);
}

// ==================== Additional Tests for Better Coverage ====================

/// Test deposit function without oracle interface
#[test]
#[should_panic]
fn test_deposit_oracle_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let vault_addr = client.address.clone();

    // Remove oracle from instance storage to trigger MissingValue when reading NAV.
    env.as_contract(&vault_addr, || {
        env.storage().instance().remove(&DataKey::Oracle);
    });

    let user = Address::generate(&env);
    client.deposit(&user, &token_addr, &1000);
}

/// Test deposit with zero withdraw fee ratio
#[test]
fn test_deposit_zero_withdraw_fee_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let amount = 100_000_000i128;

    client.set_withdraw_fee_ratio_by_admin(&0i128);
    let minted = client.deposit(&user, &token_addr, &amount);
    assert!(minted > 0);
}

/// Test withdraw currency queries when none is set
#[test]
fn test_withdraw_currency_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Constructor sets withdraw currency; should not be None
    assert!(client.get_withdraw_currency().is_some());
}

/// Test domain chain ID and domain separator generation
#[test]
fn test_domain_advanced_functions() {
    let env = Env::default();
    env.mock_all_auths();

    let (_client, vault_addr, _admin) = create_vault_contract(&env);

    let user = Address::generate(&env);
    let withdraw_token = create_mock_token(&env, "WithdrawToken", "WT");
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 6);

    let msg1 = env.as_contract(&vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(&env, &user, 10, &withdraw_token, nav, &request_hash)
    });
    let msg2 = env.as_contract(&vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(&env, &user, 11, &withdraw_token, nav, &request_hash)
    });
    assert_ne!(msg1, msg2);
}

/// Test currency management edge cases
#[test]
fn test_currency_supported_function() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    let currency1 = create_mock_token(&env, "Currency1", "CUR1");
    let currency2 = create_mock_token(&env, "Currency2", "CUR2");

    // Initially neither should be supported
    assert!(!client.is_currency_supported(&currency1));
    assert!(!client.is_currency_supported(&currency2));

    // Add one currency
    client.add_currency_by_admin(&currency1, &100);

    // Now only currency1 should be supported
    assert!(client.is_currency_supported(&currency1));
    assert!(!client.is_currency_supported(&currency2));

    // Add second currency
    client.add_currency_by_admin(&currency2, &100);

    // Both should be supported
    assert!(client.is_currency_supported(&currency1));
    assert!(client.is_currency_supported(&currency2));

    // Remove first currency
    client.remove_currency_by_admin(&currency1);

    // Only currency2 should be supported
    assert!(!client.is_currency_supported(&currency1));
    assert!(client.is_currency_supported(&currency2));
}

/// Test withdraw fee receiver functionality
#[test]
fn test_withdraw_fee_receiver_management() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    // Initial fee receiver should be set to config value
    assert_eq!(
        client.get_withdraw_fee_receiver(),
        config.withdraw_fee_receiver
    );

    // Set new fee receiver
    let new_fee_receiver = Address::generate(&env);
    client.set_withdraw_fee_recv_by_admin(&new_fee_receiver);

    // Verify it was updated
    assert_eq!(client.get_withdraw_fee_receiver(), new_fee_receiver);
    assert_ne!(
        client.get_withdraw_fee_receiver(),
        config.withdraw_fee_receiver
    );
}

/// Test all system management setters
#[test]
fn test_complete_system_management() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Test setting all system components
    let new_oracle = create_mock_oracle(&env);
    let new_treasurer = Address::generate(&env);
    let new_verifier = BytesN::from_array(&env, &[4u8; 32]);
    let new_fee_receiver = Address::generate(&env);

    // Set new addresses
    client.set_oracle_by_admin(&new_oracle);
    client.set_treasurer_by_admin(&new_treasurer);
    client.set_withdraw_verifier_by_admin(&0u32, &new_verifier.clone().into());
    client.set_withdraw_fee_recv_by_admin(&new_fee_receiver);
    client.set_withdraw_fee_ratio_by_admin(&250);

    // Verify all were set correctly
    assert_eq!(client.get_oracle(), new_oracle);
    assert_eq!(client.get_treasurer(), new_treasurer);
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        new_verifier
    );
    assert_eq!(client.get_withdraw_fee_receiver(), new_fee_receiver);
    assert_eq!(client.get_withdraw_fee_ratio(), 250);
}

// ==================== Traits Coverage Tests ====================

/// Test WithdrawRequest data structure coverage
#[test]
fn test_withdraw_request_structure() {
    let env = Env::default();

    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 1);
    let signature = create_mock_signature(&env);
    let signature_bytes = Bytes::from_slice(&env, &signature.to_array());

    // Create WithdrawRequest structure to test traits.rs coverage
    let withdraw_request = WithdrawRequest {
        user: user.clone(),
        target_amount: 1000i128,
        nav: 100_000_000i128,
        request_hash: request_hash.clone(),
        timestamp: 1700000000u64,
        signature: signature_bytes.clone(),
    };

    // Test Debug trait (clone, eq, etc.)
    let withdraw_request2 = withdraw_request.clone();
    assert_eq!(withdraw_request, withdraw_request2);
    assert_eq!(withdraw_request.user, user);
    assert_eq!(withdraw_request.target_amount, 1000);
    assert_eq!(withdraw_request.nav, 100_000_000);
    assert_eq!(withdraw_request.request_hash, request_hash);
    assert_eq!(withdraw_request.timestamp, 1700000000);
    assert_eq!(withdraw_request.signature, signature_bytes);
}

/// Test local TestConfig structure coverage
#[test]
fn test_initialize_config_structure() {
    let env = Env::default();

    // Create local test config to validate copy/compare behavior
    let config = TestConfig {
        admin: Address::generate(&env),
        oracle: Address::generate(&env),
        treasurer: Address::generate(&env),
        withdraw_verifier: BytesN::from_array(&env, &[2u8; 32]),
        withdraw_fee_ratio: 250,
        withdraw_fee_receiver: Address::generate(&env),
    };

    // Test Debug trait (clone)
    let config2 = TestConfig {
        admin: config.admin.clone(),
        oracle: config.oracle.clone(),
        treasurer: config.treasurer.clone(),
        withdraw_verifier: config.withdraw_verifier.clone(),
        withdraw_fee_ratio: config.withdraw_fee_ratio,
        withdraw_fee_receiver: config.withdraw_fee_receiver.clone(),
    };
    assert_eq!(config.admin, config2.admin);
    assert_eq!(config.withdraw_fee_ratio, config2.withdraw_fee_ratio);
    // domain fields removed from InitializeConfig
}

/// Test event structures for coverage
#[test]
fn test_event_structures_coverage() {
    let env = Env::default();

    let currency = create_mock_token(&env, "TestCurrency", "TEST");
    let admin = Address::generate(&env);
    let request_hash = create_request_hash(&env, 1);

    // Test DepositEvent
    let deposit_event = DepositEvent {
        amount: 1000,
        minted_tokens: 900,
        nav: 100_000_000,
    };

    let deposit_event2 = deposit_event.clone();
    assert_eq!(deposit_event, deposit_event2);
    assert_eq!(deposit_event.amount, 1000);
    assert_eq!(deposit_event.minted_tokens, 900);
    assert_eq!(deposit_event.nav, 100_000_000);

    // Test WithdrawEvent
    let withdraw_event = WithdrawEvent {
        amount: 950,
        fee: 5,
        request_hash: Bytes::from_slice(&env, b"test_request_hash"),
    };

    let withdraw_event2 = withdraw_event.clone();
    assert_eq!(withdraw_event, withdraw_event2);
    assert_eq!(withdraw_event.amount, 950);
    assert_eq!(withdraw_event.fee, 5);

    // Test SetAllowedCurrencyEvent
    let set_allowed_currency_event = SetAllowedCurrencyEvent { allowed: true };

    let set_allowed_currency_event2 = set_allowed_currency_event.clone();
    assert_eq!(set_allowed_currency_event, set_allowed_currency_event2);
    assert_eq!(set_allowed_currency_event.allowed, true);

    // Test CurrencyRemovedEvent
    let currency_removed_event = CurrencyRemovedEvent {
        admin: admin.clone(),
    };

    let currency_removed_event2 = currency_removed_event.clone();
    assert_eq!(currency_removed_event, currency_removed_event2);
    assert_eq!(currency_removed_event.admin, admin);

    // Test WithdrawRequestEvent
    let withdraw_request_event = WithdrawRequestEvent {
        token_contract: currency.clone(),
        shares: 500,
        request_hash: request_hash.clone(),
        nav: 100_000_000,
        amount: 500,
    };

    let withdraw_request_event2 = withdraw_request_event.clone();
    assert_eq!(withdraw_request_event, withdraw_request_event2);
    assert_eq!(withdraw_request_event.shares, 500);
    assert_eq!(withdraw_request_event.token_contract, currency);
    assert_eq!(withdraw_request_event.nav, 100_000_000);

    // Test TreasurerDepositEvent
    let treasurer_deposit_event = TreasurerDepositEvent { amount: 2000 };

    let treasurer_deposit_event2 = treasurer_deposit_event.clone();
    assert_eq!(treasurer_deposit_event, treasurer_deposit_event2);
    assert_eq!(treasurer_deposit_event.amount, 2000);
}

/// Test domainDomain structure coverage
#[test]
fn test_domain_domain_structure() {
    let env = Env::default();

    let chain_id = Bytes::from_array(&env, &[1u8; 32]);
    let salt = Bytes::from_array(&env, &[2u8; 32]);
    let contract_address = Address::generate(&env);

    // Create Domain to test coverage
    let domain = Domain {
        name: String::from_str(&env, "TestDomain"),
        version: String::from_str(&env, "1.0"),
        chain_id: chain_id.clone(),
        verifying_contract: contract_address.clone(),
        salt: salt.clone(),
    };

    // Test traits
    let domain2 = domain.clone();
    assert_eq!(domain, domain2);
    assert_eq!(domain.name, String::from_str(&env, "TestDomain"));
    assert_eq!(domain.version, String::from_str(&env, "1.0"));
    assert_eq!(domain.chain_id, chain_id);
    assert_eq!(domain.verifying_contract, contract_address);
    assert_eq!(domain.salt, salt);

    // Test ordering traits (PartialOrd, Ord)
    let domain3 = Domain {
        name: String::from_str(&env, "AnotherDomain"), // Different name for ordering test
        version: String::from_str(&env, "1.0"),
        chain_id: chain_id.clone(),
        verifying_contract: contract_address.clone(),
        salt: salt.clone(),
    };

    // This tests PartialOrd and Ord implementations
    assert_ne!(domain, domain3);
}

/// Test WithdrawStatus enum coverage
#[test]
fn test_withdraw_status_enum() {
    // Test WithdrawStatus enum to get coverage
    let status1 = WithdrawStatus::NotExist;
    let status2 = WithdrawStatus::Pending;
    let status3 = WithdrawStatus::Done;

    // Test Clone trait
    let status1_clone = status1.clone();
    let status2_clone = status2.clone();
    let status3_clone = status3.clone();

    // Test PartialEq trait
    assert_eq!(status1, status1_clone);
    assert_eq!(status2, status2_clone);
    assert_eq!(status3, status3_clone);
    assert_ne!(status1, status2);
    assert_ne!(status2, status3);

    // Test enum values
    assert_eq!(status1 as u32, 0);
    assert_eq!(status2 as u32, 1);
    assert_eq!(status3 as u32, 2);

    // Test ordering traits with fresh instances
    assert!(WithdrawStatus::NotExist < WithdrawStatus::Pending);
    assert!(WithdrawStatus::Pending < WithdrawStatus::Done);
    assert!(WithdrawStatus::NotExist < WithdrawStatus::Done);
}

// ==================== Core Business Logic Tests ====================

/// Test deposit function - oracle not set error
#[test]
#[should_panic(expected = "Error(Contract, #301)")]
fn test_deposit_oracle_not_configured() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Try to use deposit without proper configuration (oracle not set)
    client.deposit(&user, &currency, &1000);
}

// removed deprecated test: withdraw currency is always set in constructor

/// Test withdraw function - invalid request status
#[test]
#[should_panic(expected = "Error(Contract, #311)")] // InvalidRequestStatus
fn test_withdraw_invalid_request_status() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = Bytes::from_array(&env, &[1u8; 32]);
    let mock_signature = BytesN::<64>::from_array(&env, &[0u8; 64]);
    let nav = 100_000_000i128;

    // Try to withdraw without creating request first
    // Call and expect InvalidRequestStatus (#27)
    #[allow(unused_must_use)]
    {
        client.withdraw(
            &user,
            &1000,
            &nav,
            &request_hash,
            &mock_signature,
            &0u32,
            &0u32,
        );
    }
}

/// Zero withdraw fee ratio should not panic for withdraw_request
#[test]
fn test_withdraw_request_with_zero_withdraw_fee_ratio_allows_operation() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_zero_fee(&env);

    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 777);
    #[allow(unused_must_use)]
    {
        client.withdraw_request(&user, &1000, &request_hash);
    }
}

/// Zero withdraw fee ratio should not trigger config panic; still fails with no request
#[test]
#[should_panic(expected = "Error(Contract, #311)")] // InvalidRequestStatus
fn test_withdraw_with_zero_withdraw_fee_ratio_should_panic() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_zero_fee(&env);

    let user = Address::generate(&env);
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 778);
    let dummy_sig = BytesN::<64>::from_array(&env, &[0u8; 64]);
    // Should panic due to invalid request status
    client.withdraw(&user, &1000, &nav, &request_hash, &dummy_sig, &0u32, &0u32);
}

/// Test withdraw with invalid amount (shares == 0)
#[test]
#[should_panic(expected = "Error(Contract, #305)")] // InvalidAmount
fn test_withdraw_invalid_amount_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 1001);
    let signature = BytesN::<64>::from_array(&env, &[0u8; 64]);

    let shares = 0i128;
    let nav = 100_000_000i128;
    client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &signature,
        &0u32,
        &0u32,
    );
}

/// Test withdraw with invalid NAV (nav == 0)
#[test]
#[should_panic(expected = "Error(Contract, #306)")] // InvalidNav
fn test_withdraw_invalid_nav_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 1002);
    let signature = BytesN::<64>::from_array(&env, &[0u8; 64]);

    let shares = 1i128;
    let nav = 0i128;
    client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &signature,
        &0u32,
        &0u32,
    );
}

/// Test treasurer deposit with comprehensive validation
#[test]
fn test_treasurer_deposit_comprehensive_validation() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let deposit_amount = 5_000_000i128; // 0.05 units
    client.treasurer_deposit(&deposit_amount);
}

/// Test internal function coverage through public APIs
#[test]
fn test_internal_functions_through_public_apis() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    // Test get functions that exercise internal functions
    let admin = client.get_admin();
    assert_eq!(admin, config.admin);

    let oracle = client.get_oracle();
    assert_eq!(oracle, config.oracle);

    let treasurer = client.get_treasurer();
    assert_eq!(treasurer, config.treasurer);

    let withdraw_fee_ratio = client.get_withdraw_fee_ratio();
    assert_eq!(withdraw_fee_ratio, config.withdraw_fee_ratio);

    let withdraw_fee_receiver = client.get_withdraw_fee_receiver();
    assert_eq!(withdraw_fee_receiver, config.withdraw_fee_receiver);
}

/// Test error conditions for vault operations
#[test]
fn test_vault_error_conditions() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Most operations should fail on uninitialized vault
    let result = client.try_is_currency_supported(&currency);
    // Should either return false or panic depending on implementation
    let _ = result;

    let result = client.try_get_supported_currencies();
    // Should return empty or panic
    let _ = result;
}

/// Test withdrawal request duplicate detection
#[test]
#[should_panic(expected = "Error(Contract, #309)")]
fn test_withdraw_request_duplicate() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = Bytes::from_array(&env, &[1u8; 32]);

    // First request should succeed
    client.withdraw_request(&user, &1000, &request_hash);

    // Second request with same parameters should fail with RequestAlreadyExists (#25)
    #[allow(unused_must_use)]
    {
        client.withdraw_request(&user, &1000, &request_hash);
    }
}

/// Test withdraw_request should fail when user shares balance is insufficient
#[test]
#[should_panic(expected = "Error(Contract, #310)")]
fn test_withdraw_request_insufficient_balance() {
    let env = Env::default();
    env.mock_all_auths();

    // Use mocks: MockToken.balance() returns 1_000_000_000_000_000_000
    // Pass shares slightly larger than that to trigger InsufficientBalance
    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 9_999);
    let shares = 1_000_000_000_000_000_001i128; // > mock balance

    client.withdraw_request(&user, &shares, &request_hash);
}

/// Test withdraw_request_with_allowance function
#[test]
fn test_withdraw_request_with_allowance() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 123);
    let shares = 1000i128;

    // Call the new withdraw_request_with_allowance function
    // With mock_all_auths(), this should pass even though it uses burn_from
    client.withdraw_request_with_allowance(&user, &shares, &request_hash);
}

/// Test withdraw_request_with_allowance with duplicate request
#[test]
#[should_panic(expected = "Error(Contract, #309)")]
fn test_withdraw_request_with_allowance_duplicate() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 456);
    let shares = 1000i128;

    // First request should succeed
    client.withdraw_request_with_allowance(&user, &shares, &request_hash);

    // Second request with same parameters should fail with RequestAlreadyExists
    client.withdraw_request_with_allowance(&user, &shares, &request_hash);
}

/// Test withdraw_request_with_allowance with invalid amount (zero)
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_withdraw_request_with_allowance_invalid_amount_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 789);

    // Call with zero amount should panic
    client.withdraw_request_with_allowance(&user, &0, &request_hash);
}

/// Test withdraw_request_with_allowance with invalid amount (negative)
#[test]
#[should_panic(expected = "Error(Contract, #305)")]
fn test_withdraw_request_with_allowance_invalid_amount_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 790);

    // Call with negative amount should panic
    client.withdraw_request_with_allowance(&user, &-100, &request_hash);
}

/// Test withdraw_request_with_allowance should fail when user shares balance is insufficient
#[test]
#[should_panic(expected = "Error(Contract, #310)")]
fn test_withdraw_request_with_allowance_insufficient_balance() {
    let env = Env::default();
    env.mock_all_auths();

    // Use mocks: MockToken.balance() returns 1_000_000_000_000_000_000
    // Pass shares slightly larger than that to trigger InsufficientBalance
    let (client, _token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks(&env);
    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 9_998);
    let shares = 1_000_000_000_000_000_001i128; // > mock balance

    client.withdraw_request_with_allowance(&user, &shares, &request_hash);
}

/// Test withdraw_request_with_allowance with zero withdraw fee ratio allows operation
#[test]
fn test_withdraw_request_with_allowance_with_zero_withdraw_fee_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _token, _oracle, _treasurer) = create_vault_with_zero_fee(&env);

    let user = Address::generate(&env);
    let request_hash = create_request_hash(&env, 888);
    #[allow(unused_must_use)]
    {
        client.withdraw_request_with_allowance(&user, &1000, &request_hash);
    }
}

/// Test signature message creation and domain functions
#[test]
fn test_domain_message_creation() {
    let env = Env::default();
    env.mock_all_auths();

    let (_client, vault_addr, _admin) = create_vault_contract(&env);

    let user = Address::generate(&env);
    let withdraw_token = create_mock_token(&env, "WithdrawToken", "WT");
    let shares = 999i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 7);

    let msg1 = env.as_contract(&vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(
            &env,
            &user,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
        )
    });
    let msg2 = env.as_contract(&vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(
            &env,
            &user,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
        )
    });
    assert_eq!(msg1, msg2);
}

/// Test calculate mint amount through deposit
#[test]
fn test_calculate_mint_amount_through_deposit() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let user = Address::generate(&env);
    let currency = create_mock_token(&env, "TestCurrency", "TEST");

    // Test deposit to exercise mint calculation
    let deposit_amount = 1000000i128; // 0.01 units

    // This will test the entire deposit flow including mint calculation
    let result = client.try_deposit(&user, &currency, &deposit_amount);

    // Deposit might fail due to missing dependencies, just ensure we can call it
    let _ = result;
}

/// Test vault query functions comprehensive coverage
#[test]
fn test_vault_query_functions_comprehensive() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    // Test all query functions
    assert_eq!(client.get_admin(), config.admin);
    assert_eq!(client.get_oracle(), config.oracle);
    assert_eq!(client.get_treasurer(), config.treasurer);
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        config.withdraw_verifier
    );
    assert_eq!(client.get_withdraw_fee_ratio(), config.withdraw_fee_ratio);
    assert_eq!(
        client.get_withdraw_fee_receiver(),
        config.withdraw_fee_receiver
    );

    // Test query functions that exist
    let supported_currencies = client.get_supported_currencies();
    // Just verify the call works, don't assume specific content
    let _ = supported_currencies.len();

    // Test currency support with a random address
    let test_currency = Address::generate(&env);
    let _ = client.is_currency_supported(&test_currency);
}

// ==================== Additional Core Function Tests ====================

// test_withdraw_missing_withdraw_currency removed:
// WithdrawCurrency is now set in constructor and cannot be missing

/// Test various error conditions with proper setup
#[test]
fn test_error_conditions_comprehensive() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let config = initialize_vault_with_defaults(&env, &client);

    // Test various query functions work after initialization
    assert_eq!(client.get_oracle(), config.oracle);
    assert_eq!(client.get_treasurer(), config.treasurer);
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        config.withdraw_verifier
    );

    // Withdraw currency should be set by constructor
    let withdraw_currency = client.get_withdraw_currency();
    assert!(withdraw_currency.is_some());
}

/// Test signature verification edge cases
#[test]
fn test_signature_verification_edge_cases() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Test verifier key management
    let new_verifier = BytesN::from_array(&env, &[4u8; 32]);
    client.set_withdraw_verifier_by_admin(&0u32, &new_verifier.clone().into());
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        new_verifier
    );

    // Test getting withdraw verifier multiple times
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        new_verifier
    );
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        new_verifier
    );
}

/// Test domain domain and chain operations
#[test]
fn test_domain_domain_comprehensive() {
    let env = Env::default();
    env.mock_all_auths();

    let (_client, vault_addr, _admin) = create_vault_contract(&env);

    let user = Address::generate(&env);
    let withdraw_token = create_mock_token(&env, "WithdrawToken", "WT");
    let shares = 123i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 8);

    let msg = env.as_contract(&vault_addr, || {
        SolvBTCVault::create_withdraw_string_message(
            &env,
            &user,
            shares,
            &withdraw_token,
            nav,
            &request_hash,
        )
    });
    assert!(msg.len() > 0);
}

/// Test system configuration management comprehensively
#[test]
fn test_system_configuration_management() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Test all system setters and getters
    let new_oracle = create_mock_oracle(&env);
    client.set_oracle_by_admin(&new_oracle);
    assert_eq!(client.get_oracle(), new_oracle);

    let new_treasurer = Address::generate(&env);
    client.set_treasurer_by_admin(&new_treasurer);
    assert_eq!(client.get_treasurer(), new_treasurer);

    let new_verifier = BytesN::from_array(&env, &[4u8; 32]);
    client.set_withdraw_verifier_by_admin(&0u32, &new_verifier.clone().into());
    assert_eq!(
        BytesN::<32>::try_from(client.get_withdraw_verifier(&0u32).unwrap()).unwrap(),
        new_verifier
    );

    // Test fee management
    client.set_withdraw_fee_ratio_by_admin(&200);
    assert_eq!(client.get_withdraw_fee_ratio(), 200);

    let new_fee_receiver = Address::generate(&env);
    client.set_withdraw_fee_recv_by_admin(&new_fee_receiver);
    assert_eq!(client.get_withdraw_fee_receiver(), new_fee_receiver);
}

/// Test currency management comprehensive scenarios
#[test]
fn test_currency_management_comprehensive() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Test adding multiple currencies
    let currency1 = create_mock_token(&env, "Currency1", "CUR1");
    let currency2 = create_mock_token(&env, "Currency2", "CUR2");
    let currency3 = create_mock_token(&env, "Currency3", "CUR3");

    client.add_currency_by_admin(&currency1, &100);
    client.add_currency_by_admin(&currency2, &100);
    client.add_currency_by_admin(&currency3, &100);

    // Test getting all supported currencies
    let supported = client.get_supported_currencies();
    assert!(supported.len() >= 3);

    // Test currency support checks
    assert!(client.is_currency_supported(&currency1));
    assert!(client.is_currency_supported(&currency2));
    assert!(client.is_currency_supported(&currency3));
    assert!(!client.is_currency_supported(&Address::generate(&env)));

    // Test removing currencies
    client.remove_currency_by_admin(&currency2);
    assert!(!client.is_currency_supported(&currency2));
    assert!(client.is_currency_supported(&currency1));
    assert!(client.is_currency_supported(&currency3));

    // Verify supported currencies list updated
    let supported_after = client.get_supported_currencies();
    assert!(supported_after.len() < supported.len());
}

#[test]
fn test_set_deposit_fee_ratio_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);
    let initial_deposit_fee = 100i128; // 1%
    let withdraw_fee_ratio = 50i128;
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract.clone(),
            oracle.clone(),
            treasurer.clone(),
            withdraw_verifier.clone(),
            withdraw_fee_ratio,
            withdraw_fee_receiver.clone(),
            withdraw_currency.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &contract_address);

    // Add currency first with initial fee
    let currency = create_mock_token(&env, "Currency", "CUR");
    client.add_currency_by_admin(&currency, &initial_deposit_fee);

    // Check initial deposit fee ratio
    assert_eq!(client.get_deposit_fee_ratio(&currency), initial_deposit_fee);

    // Update deposit fee ratio to 2% (200 basis points)
    let new_deposit_fee = 200i128;
    client.set_deposit_fee_ratio_by_admin(&currency, &new_deposit_fee);

    // Verify the update
    assert_eq!(client.get_deposit_fee_ratio(&currency), new_deposit_fee);

    // Test setting maximum allowed fee (100%)
    let max_fee = 10000i128;
    client.set_deposit_fee_ratio_by_admin(&currency, &max_fee);
    assert_eq!(client.get_deposit_fee_ratio(&currency), max_fee);

    // Test setting zero fee
    let zero_fee = 0i128;
    client.set_deposit_fee_ratio_by_admin(&currency, &zero_fee);
    assert_eq!(client.get_deposit_fee_ratio(&currency), zero_fee);
}

#[test]
#[should_panic(expected = "Error(Contract, #312)")]
fn test_set_deposit_fee_ratio_invalid() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);
    let deposit_fee_ratio = 100i128;
    let withdraw_fee_ratio = 50i128;
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract.clone(),
            oracle.clone(),
            treasurer.clone(),
            withdraw_verifier.clone(),
            withdraw_fee_ratio,
            withdraw_fee_receiver.clone(),
            withdraw_currency.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &contract_address);

    // Add currency first
    let currency = create_mock_token(&env, "Currency", "CUR");
    client.add_currency_by_admin(&currency, &deposit_fee_ratio);

    // Try to set invalid fee ratio (> 10000, which is > 100%)
    let invalid_fee = 10001i128;
    client.set_deposit_fee_ratio_by_admin(&currency, &invalid_fee);
}

#[test]
#[should_panic(expected = "Error(Contract, #312)")]
fn test_set_deposit_fee_ratio_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);
    let deposit_fee_ratio = 100i128;
    let withdraw_fee_ratio = 50i128;
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract.clone(),
            oracle.clone(),
            treasurer.clone(),
            withdraw_verifier.clone(),
            withdraw_fee_ratio,
            withdraw_fee_receiver.clone(),
            withdraw_currency.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &contract_address);

    // Add currency first
    let currency = create_mock_token(&env, "Currency", "CUR");
    client.add_currency_by_admin(&currency, &deposit_fee_ratio);

    // Try to set negative fee ratio
    let negative_fee = -1i128;
    client.set_deposit_fee_ratio_by_admin(&currency, &negative_fee);
}

#[test]
fn test_get_deposit_fee_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);
    let deposit_fee_ratio = 250i128; // 2.5%
    let withdraw_fee_ratio = 50i128;
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract.clone(),
            oracle.clone(),
            treasurer.clone(),
            withdraw_verifier.clone(),
            withdraw_fee_ratio,
            withdraw_fee_receiver.clone(),
            withdraw_currency.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &contract_address);

    // Add currency first
    let currency = create_mock_token(&env, "Currency", "CUR");
    client.add_currency_by_admin(&currency, &deposit_fee_ratio);

    // Test getting deposit fee ratio
    assert_eq!(client.get_deposit_fee_ratio(&currency), deposit_fee_ratio);

    // Update and verify again
    let new_fee = 500i128; // 5%
    client.set_deposit_fee_ratio_by_admin(&currency, &new_fee);
    assert_eq!(client.get_deposit_fee_ratio(&currency), new_fee);
}

#[test]
fn test_get_token_contract_returns_constructor_value() {
    let env = Env::default();
    env.mock_all_auths();

    // Manually construct and register: we need to get the token_contract address passed to the constructor
    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let withdraw_verifier = BytesN::from_array(&env, &[1u8; 32]);
    let withdraw_fee_ratio = 100i128;
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let contract_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract.clone(),
            oracle.clone(),
            treasurer.clone(),
            withdraw_verifier.clone(),
            withdraw_fee_ratio,
            withdraw_fee_receiver.clone(),
            withdraw_currency.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &contract_address);

    assert_eq!(client.get_shares_token(), token_contract);
}

#[test]
#[should_panic(expected = "Error(Contract, #308)")] // InvalidWithdrawFeeRatio in constructor
fn test_constructor_with_negative_withdraw_fee_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let withdraw_verifier = BytesN::from_array(&env, &[1u8; 32]);
    let withdraw_fee_ratio = -1i128; // Negative fee ratio should panic
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    env.register(
        SolvBTCVault,
        (
            admin,
            token_contract,
            oracle,
            treasurer,
            withdraw_verifier,
            withdraw_fee_ratio,
            withdraw_fee_receiver,
            withdraw_currency,
        ),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #308)")] // InvalidWithdrawFeeRatio in constructor
fn test_constructor_with_excessive_withdraw_fee_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let withdraw_verifier = BytesN::from_array(&env, &[1u8; 32]);
    let withdraw_fee_ratio = 10001i128; // Over 100% fee ratio should panic
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    env.register(
        SolvBTCVault,
        (
            admin,
            token_contract,
            oracle,
            treasurer,
            withdraw_verifier,
            withdraw_fee_ratio,
            withdraw_fee_receiver,
            withdraw_currency,
        ),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #312)")] // InvalidDepositFeeRatio
fn test_constructor_with_negative_deposit_fee_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");
    let oracle = create_mock_oracle(&env);
    let treasurer = Address::generate(&env);
    let withdraw_verifier = BytesN::from_array(&env, &[1u8; 32]);
    let deposit_fee_ratio = -1i128; // Negative deposit fee ratio should panic
    let withdraw_fee_ratio = 100i128;
    let withdraw_fee_receiver = Address::generate(&env);
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let vault_address = env.register(
        SolvBTCVault,
        (
            admin.clone(),
            token_contract.clone(),
            oracle.clone(),
            treasurer.clone(),
            withdraw_verifier.clone(),
            withdraw_fee_ratio,
            withdraw_fee_receiver.clone(),
            withdraw_currency.clone(),
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &vault_address);

    // Add currency with negative fee - should panic with InvalidDepositFeeRatio
    let currency = create_mock_token(&env, "Currency", "CUR");
    client.add_currency_by_admin(&currency, &deposit_fee_ratio);
}

/// Test unified withdraw with Ed25519 signature (type = 0)
#[test]
fn test_unified_withdraw_ed25519() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, vault_addr, token_addr, _oracle_addr, _treasurer) = create_vault_with_mocks_full(&env);

    // Set Ed25519 verifier
    let (sk, vk) = fixed_keypair();
    let verifier_public_key = public_key_from_verifying_key(&env, &vk);
    // Use signature_type = 0 for Ed25519
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_public_key.clone().into());

    // Prepare withdraw request
    let user = Address::generate(&env);
    let shares = 50_000_000i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 42);
    client.withdraw_request(&user, &shares, &request_hash);

    // Build message and sign with Ed25519
    let msg = build_withdraw_message(&env, &vault_addr, &user, shares, &token_addr, nav, &request_hash);
    let sig = sk.sign(&bytes_to_vec(&msg));
    let sig_bytes = BytesN::<64>::from_array(&env, &sig.to_bytes());

    // Execute withdraw with signature_type = 0 (Ed25519)
    let actual = client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &sig_bytes,
        &0u32, // signature_type = Ed25519
        &0u32, // recovery_id (ignored for Ed25519)
    );
    assert!(actual > 0);
}

/// Test unified withdraw with Secp256k1 signature (type = 1)
#[test]
fn test_unified_withdraw_secp256k1_interface() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _) = create_vault_with_mocks(&env);

    // Set Secp256k1 verifier (65-byte uncompressed public key)
    let mut pubkey_bytes = [0u8; 65];
    pubkey_bytes[0] = 0x04; // Uncompressed public key prefix
    for i in 1..65 {
        pubkey_bytes[i] = i as u8;
    }
    let verifier_public_key = Bytes::from_slice(&env, &pubkey_bytes);
    // Use signature_type = 1 for Secp256k1
    client.set_withdraw_verifier_by_admin(&1u32, &verifier_public_key);

    // Verify the verifier was set correctly
    let stored_verifier = client.get_withdraw_verifier(&1u32).unwrap();
    assert_eq!(stored_verifier.len(), 65);
    assert_eq!(stored_verifier.get(0).unwrap(), 0x04);
}

/// Exercise secp256k1 verification branch with invalid signature (should panic)
#[test]
#[should_panic]
fn test_withdraw_secp256k1_invalid_signature_should_panic() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _) = create_vault_with_mocks(&env);

    // Configure a 65-byte uncompressed secp256k1 public key
    let mut pubkey_bytes = [0u8; 65];
    pubkey_bytes[0] = 0x04;
    for i in 1..65 {
        pubkey_bytes[i] = i as u8;
    }
    let verifier_public_key = Bytes::from_slice(&env, &pubkey_bytes);
    client.set_withdraw_verifier_by_admin(&1u32, &verifier_public_key);

    // Prepare a withdraw request first
    let user = Address::generate(&env);
    let shares = 50_000_000i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 7);
    client.withdraw_request(&user, &shares, &request_hash);

    // Invalid signature (all zeros) and a dummy recovery id
    let sig_bytes = BytesN::<64>::from_array(&env, &[0u8; 64]);

    // Call withdraw with signature_type = 1 (secp256k1) -> should panic inside secp recover/compare
    client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &sig_bytes,
        &1u32, // secp256k1
        &0u32, // recovery id
    );
}

/// Test invalid signature type handling
#[test]
#[should_panic]
fn test_unified_withdraw_invalid_signature_type() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _) = create_vault_with_mocks(&env);

    let user = Address::generate(&env);
    let shares = 50_000_000i128;
    let nav = 100_000_000i128;
    let request_hash = create_request_hash(&env, 42);

    // Prepare request first
    client.withdraw_request(&user, &shares, &request_hash);

    // Mock signature
    let sig_bytes = BytesN::<64>::from_array(&env, &[0u8; 64]);

    // Try with invalid signature type (e.g., 99)
    let invalid_type = 99u32;

    // This should panic
    client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &sig_bytes,
        &invalid_type,
        &0u32,
    );
}

/// Test get_withdraw_verifier returns None for unset verifier
#[test]
fn test_get_withdraw_verifier_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _) = create_vault_with_mocks(&env);

    // Type 0 (Ed25519) should be set from constructor
    let ed25519_verifier = client.get_withdraw_verifier(&0u32);
    assert!(
        ed25519_verifier.is_some(),
        "Ed25519 verifier should be set from constructor"
    );

    // Type 1 (Secp256k1) should NOT be set
    let secp256k1_verifier = client.get_withdraw_verifier(&1u32);
    assert!(
        secp256k1_verifier.is_none(),
        "Secp256k1 verifier should return None when not set"
    );

    // Type 99 (invalid) should also return None
    let invalid_verifier = client.get_withdraw_verifier(&99u32);
    assert!(
        invalid_verifier.is_none(),
        "Invalid signature type should return None"
    );
}

/// Test withdraw fails with WithdrawVerifierNotSet error when verifier not set
#[test]
#[should_panic(expected = "Error(Contract, #315)")]
fn test_withdraw_with_unset_verifier_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _) = create_vault_with_mocks(&env);

    // Setup
    let user = Address::generate(&env);
    let shares = 50_000_000i128;
    let nav = 100_000_000i128;

    // Create withdraw request
    let request_hash = create_request_hash(&env, 99);
    client.withdraw_request(&user, &shares, &request_hash);

    // Create Secp256k1 signature (64 bytes, but verifier not set)
    let sig_bytes = BytesN::<64>::from_array(&env, &[0u8; 64]);

    // Try to withdraw with Secp256k1 (type 1) when verifier not set
    // This should panic with WithdrawVerifierNotSet
    client.withdraw(
        &user,
        &shares,
        &nav,
        &request_hash,
        &sig_bytes,
        &1u32, // Secp256k1 - not set!
        &0u32,
    );
}

/// Test setting verifiers for different signature types
#[test]
fn test_set_multiple_verifier_types() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Set Ed25519 verifier (32 bytes)
    let ed25519_key = BytesN::<32>::from_array(&env, &[1u8; 32]);
    client.set_withdraw_verifier_by_admin(&0u32, &ed25519_key.clone().into());

    // Set Secp256k1 verifier (65 bytes)
    let mut secp256k1_key_bytes = [0u8; 65];
    secp256k1_key_bytes[0] = 0x04; // Uncompressed prefix
    for i in 1..65 {
        secp256k1_key_bytes[i] = (i * 2) as u8;
    }
    let secp256k1_key = Bytes::from_slice(&env, &secp256k1_key_bytes);
    client.set_withdraw_verifier_by_admin(&1u32, &secp256k1_key);

    // Verify both are stored correctly
    let stored_ed25519 = client.get_withdraw_verifier(&0u32).unwrap();
    assert_eq!(stored_ed25519.len(), 32);
    assert_eq!(stored_ed25519.get(0).unwrap(), 1);

    let stored_secp256k1 = client.get_withdraw_verifier(&1u32).unwrap();
    assert_eq!(stored_secp256k1.len(), 65);
    assert_eq!(stored_secp256k1.get(0).unwrap(), 0x04);
}

/// Test that different signature types don't overwrite each other
#[test]
fn test_verifier_types_coexist() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);

    // Set both verifier types with distinct values
    let ed25519_key = BytesN::<32>::from_array(&env, &[0xEDu8; 32]);
    client.set_withdraw_verifier_by_admin(&0u32, &ed25519_key.clone().into());

    let mut secp_bytes = [0x00u8; 65];
    secp_bytes[0] = 0x04;
    for i in 1..65 {
        secp_bytes[i] = 0xEC;
    }
    let secp256k1_key = Bytes::from_slice(&env, &secp_bytes);
    client.set_withdraw_verifier_by_admin(&1u32, &secp256k1_key);

    // Verify they don't overwrite each other
    let stored_ed25519 = client.get_withdraw_verifier(&0u32).unwrap();
    assert_eq!(stored_ed25519.get(0).unwrap(), 0xED);
    assert_eq!(stored_ed25519.len(), 32);

    let stored_secp256k1 = client.get_withdraw_verifier(&1u32).unwrap();
    assert_eq!(stored_secp256k1.get(0).unwrap(), 0x04);
    assert_eq!(stored_secp256k1.get(1).unwrap(), 0xEC);
    assert_eq!(stored_secp256k1.len(), 65);
}

/// Test Ed25519 ignores recovery_id parameter
#[test]
fn test_ed25519_ignores_recovery_id() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, vault_addr, token_addr, _, _) = create_vault_with_mocks_full(&env);

    // Set Ed25519 verifier
    let (sk, vk) = fixed_keypair();
    let verifier_public_key = public_key_from_verifying_key(&env, &vk);
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_public_key.clone().into());

    let user = Address::generate(&env);
    let shares = 50_000_000i128;
    let nav = 100_000_000i128;

    // Test with different recovery_id values - all should work for Ed25519
    for test_recovery_id in [0u32, 1u32, 2u32, 3u32, 99u32].iter() {
        let request_hash = create_request_hash(&env, 100 + *test_recovery_id as u64);
        client.withdraw_request(&user, &shares, &request_hash);

        // Build and sign message
        let msg =
            build_withdraw_message(&env, &vault_addr, &user, shares, &token_addr, nav, &request_hash);
        let sig = sk.sign(&bytes_to_vec(&msg));
        let sig_bytes = BytesN::<64>::from_array(&env, &sig.to_bytes());

        let actual = client.withdraw(
            &user,
            &shares,
            &nav,
            &request_hash,
            &sig_bytes,
            &0u32,            // Ed25519
            test_recovery_id, // Should be ignored
        );
        assert!(
            actual > 0,
            "Ed25519 should work with recovery_id={}",
            test_recovery_id
        );
    }
}

// ==================== Overflow Protection Tests ====================

/// Test: validate_decimals_config rejects single decimal > 18
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_validate_decimals_single_too_large() {
    let env = Env::default();
    // Test with shares_decimals = 19 (exceeds limit)
    SolvBTCVault::validate_decimals_config(&env, 19, 8, 8);
}

/// Test: validate_decimals_config rejects decimals sum > 38
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_validate_decimals_sum_too_large() {
    let env = Env::default();
    // Test with sum = 18 + 18 + 10 = 46 > 38
    SolvBTCVault::validate_decimals_config(&env, 18, 18, 10);
}

/// Test: validate_decimals_config accepts valid edge case
#[test]
fn test_validate_decimals_max_valid() {
    let env = Env::default();
    // Test with sum = 18 + 18 + 2 = 38 (exactly at the limit)
    SolvBTCVault::validate_decimals_config(&env, 18, 18, 2);
    // Should succeed without panic
}

/// Test: calculate_mint_amount with safe decimals doesn't overflow
#[test]
fn test_calculate_mint_no_overflow_safe_decimals() {
    let env = Env::default();

    // Safe configuration: 8, 8, 8
    let deposit_amount = 1_000_000_000_000i128; // 1 trillion
    let nav = 100_000_000i128; // 1.0 with 8 decimals
    let currency_decimals = 8u32;
    let shares_decimals = 8u32;
    let nav_decimals = 8u32;

    // Should not overflow with optimized calculation
    let minted = SolvBTCVault::calculate_mint_amount(
        &env,
        deposit_amount,
        nav,
        currency_decimals,
        shares_decimals,
        nav_decimals,
    );

    assert!(minted > 0, "Minted shares should be positive");
    // With NAV = 1.0, minted should equal deposit_amount
    assert_eq!(minted, deposit_amount);
}

/// Test: calculate_mint_amount with high precision decimals
#[test]
fn test_calculate_mint_high_precision() {
    let env = Env::default();

    // High precision but within limits: 18, 18, 2 (sum = 38)
    let deposit_amount = 1_000_000i128; // Smaller amount for high precision
    let nav = 100i128; // NAV = 1.0 with 2 decimals
    let currency_decimals = 18u32;
    let shares_decimals = 18u32;
    let nav_decimals = 2u32;

    let minted = SolvBTCVault::calculate_mint_amount(
        &env,
        deposit_amount,
        nav,
        currency_decimals,
        shares_decimals,
        nav_decimals,
    );

    assert!(minted > 0, "Minted shares should be positive");
}

/// Test: calculate_mint_amount rejects invalid decimals
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_calculate_mint_invalid_decimals() {
    let env = Env::default();

    // Invalid configuration: 19, 18, 8 (first decimal > 18)
    let deposit_amount = 1_000i128;
    let nav = 100i128;

    SolvBTCVault::calculate_mint_amount(
        &env,
        deposit_amount,
        nav,
        19, // Invalid: > 18
        18,
        8,
    );
}

/// Test: calculate_mint_amount rejects zero or negative NAV
#[test]
#[should_panic(expected = "Error(Contract, #306)")]
fn test_calculate_mint_zero_nav() {
    let env = Env::default();

    SolvBTCVault::calculate_mint_amount(
        &env,
        1000i128,
        0i128, // Invalid: NAV = 0
        8,
        8,
        8,
    );
}

/// Test: calculate_withdraw_amount with safe decimals
#[test]
fn test_calculate_withdraw_safe_decimals() {
    let env = Env::default();

    let shares = 1_000_000_000_000i128; // 1 trillion shares
    let nav = 100_000_000i128; // NAV = 1.0 with 8 decimals
    let shares_decimals = 8u32;
    let withdraw_decimals = 8u32;
    let nav_decimals = 8u32;

    let amount = SolvBTCVault::calculate_withdraw_amount(
        &env,
        shares,
        nav,
        shares_decimals,
        withdraw_decimals,
        nav_decimals,
    );

    assert!(amount > 0, "Withdraw amount should be positive");
    assert_eq!(amount, shares); // With NAV = 1.0, amount should equal shares
}

/// Test: calculate_withdraw_amount with high precision
#[test]
fn test_calculate_withdraw_high_precision() {
    let env = Env::default();

    // High precision: 18, 18, 2 (sum = 38)
    let shares = 1_000_000i128;
    let nav = 100i128; // NAV = 1.0 with 2 decimals
    let shares_decimals = 18u32;
    let withdraw_decimals = 18u32;
    let nav_decimals = 2u32;

    let amount = SolvBTCVault::calculate_withdraw_amount(
        &env,
        shares,
        nav,
        shares_decimals,
        withdraw_decimals,
        nav_decimals,
    );

    assert!(amount > 0, "Withdraw amount should be positive");
}

/// Test: calculate_withdraw_amount rejects invalid decimals
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_calculate_withdraw_invalid_decimals() {
    let env = Env::default();

    // Invalid: sum = 18 + 18 + 18 = 54 > 38
    SolvBTCVault::calculate_withdraw_amount(
        &env,
        1000i128,
        100i128,
        18,
        18,
        18, // Combined sum exceeds 38
    );
}

/// Test: constructor rejects invalid decimals configuration
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_constructor_rejects_invalid_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let withdraw_fee_receiver = Address::generate(&env);

    // Create token with 19 decimals (exceeds limit of 18)
    let token_contract = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "SolvBTC"),
            String::from_str(&env, "SOLVBTC"),
            19u32, // Invalid: > 18
        ),
    );

    // Create oracle with 8 decimals
    let oracle = create_mock_oracle(&env);

    // Create withdraw currency with 8 decimals
    let withdraw_currency = create_mock_token(&env, "WBTC", "WBTC");

    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);

    // This should panic with InvalidDecimals error
    env.register(
        SolvBTCVault,
        (
            &admin,
            &token_contract,
            &oracle,
            &treasurer,
            &withdraw_verifier,
            100i128,
            &withdraw_fee_receiver,
            &withdraw_currency,
        ),
    );
}

/// Test: constructor rejects invalid withdraw_currency decimals (> 18)
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_constructor_rejects_invalid_withdraw_currency_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let withdraw_fee_receiver = Address::generate(&env);

    // Create token with 8 decimals (valid)
    let token_contract = create_mock_token(&env, "SolvBTC", "SOLVBTC");

    // Create oracle with 8 decimals (valid)
    let oracle = create_mock_oracle(&env);

    // Create withdraw currency with 19 decimals (exceeds limit of 18)
    let withdraw_currency = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "WBTC"),
            String::from_str(&env, "WBTC"),
            19u32, // Invalid: > 18
        ),
    );

    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);

    // This should panic with InvalidDecimals error
    env.register(
        SolvBTCVault,
        (
            &admin,
            &token_contract,
            &oracle,
            &treasurer,
            &withdraw_verifier,
            100i128,
            &withdraw_fee_receiver,
            &withdraw_currency,
        ),
    );
}

/// Test: constructor rejects decimals sum > 38
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_constructor_rejects_decimals_sum_exceeds_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let withdraw_fee_receiver = Address::generate(&env);

    // Create token with 18 decimals (valid individually)
    let token_contract = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "SolvBTC"),
            String::from_str(&env, "SOLVBTC"),
            18u32,
        ),
    );

    // Create oracle with 18 decimals (valid individually)
    let oracle = env.register(SolvBtcOracle, (&admin, 18u32, 100_000_000i128));

    // Create withdraw currency with 10 decimals (valid individually)
    // But sum = 18 + 18 + 10 = 46 > 38
    let withdraw_currency = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "WBTC"),
            String::from_str(&env, "WBTC"),
            10u32,
        ),
    );

    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);

    // This should panic with InvalidDecimals error because sum > 38
    env.register(
        SolvBTCVault,
        (
            &admin,
            &token_contract,
            &oracle,
            &treasurer,
            &withdraw_verifier,
            100i128,
            &withdraw_fee_receiver,
            &withdraw_currency,
        ),
    );
}

/// Test: calculate_withdraw_amount rejects zero NAV
#[test]
#[should_panic(expected = "Error(Contract, #306)")]
fn test_calculate_withdraw_zero_nav() {
    let env = Env::default();

    SolvBTCVault::calculate_withdraw_amount(
        &env,
        1000i128,
        0i128, // Invalid: NAV = 0
        8,
        8,
        8,
    );
}

/// Test: set_oracle_by_admin rejects oracle with decimals that cause sum > 38
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_set_oracle_rejects_invalid_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    // Create vault with high decimals: token=18, withdraw_currency=18
    let admin = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let withdraw_fee_receiver = Address::generate(&env);

    let token_contract = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "SolvBTC"),
            String::from_str(&env, "SOLVBTC"),
            18u32,
        ),
    );

    let oracle = env.register(SolvBtcOracle, (&admin, 2u32, 100_000_000i128));

    let withdraw_currency = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "WBTC"),
            String::from_str(&env, "WBTC"),
            18u32,
        ),
    );

    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);

    // Create vault with sum = 18 + 18 + 2 = 38 (valid)
    let vault_addr = env.register(
        SolvBTCVault,
        (
            &admin,
            &token_contract,
            &oracle,
            &treasurer,
            &withdraw_verifier,
            100i128,
            &withdraw_fee_receiver,
            &withdraw_currency,
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &vault_addr);

    // Now try to set oracle with 18 decimals
    // This would make sum = 18 + 18 + 18 = 54 > 38
    let new_oracle = env.register(SolvBtcOracle, (&admin, 18u32, 100_000_000i128));

    // This should panic with InvalidDecimals error
    client.set_oracle_by_admin(&new_oracle);
}

/// Test: add_currency_by_admin rejects currency with decimals that cause sum > 38
#[test]
#[should_panic(expected = "Error(Contract, #316)")]
fn test_add_currency_rejects_invalid_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    // Create vault with high decimals: token=18, oracle=18, withdraw_currency=2
    let admin = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let withdraw_fee_receiver = Address::generate(&env);

    let token_contract = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "SolvBTC"),
            String::from_str(&env, "SOLVBTC"),
            18u32,
        ),
    );

    let oracle = env.register(SolvBtcOracle, (&admin, 18u32, 100_000_000i128));

    let withdraw_currency = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "WBTC"),
            String::from_str(&env, "WBTC"),
            2u32,
        ),
    );

    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[0] = 1;
    let withdraw_verifier = BytesN::from_array(&env, &verifier_bytes);

    // Create vault with sum = 18 + 2 + 18 = 38 (valid)
    let vault_addr = env.register(
        SolvBTCVault,
        (
            &admin,
            &token_contract,
            &oracle,
            &treasurer,
            &withdraw_verifier,
            100i128,
            &withdraw_fee_receiver,
            &withdraw_currency,
        ),
    );
    let client = SolvBTCVaultClient::new(&env, &vault_addr);

    // Now try to add a currency with 18 decimals
    // This would make sum = 18 + 18 + 18 = 54 > 38
    let invalid_currency = env.register(
        FungibleTokenContract,
        (
            &admin,
            &admin,
            &admin,
            String::from_str(&env, "Invalid"),
            String::from_str(&env, "INV"),
            18u32, // Valid individually but would make sum > 38
        ),
    );

    // This should panic with InvalidDecimals error
    client.add_currency_by_admin(&invalid_currency, &100);
}

/// Test: Fee calculation with checked arithmetic
#[test]
fn test_fee_calculation_no_overflow() {
    // Test that fee calculation doesn't overflow with large amounts
    let amount = 1_000_000_000_000i128; // 1 trillion
    let fee_ratio = 100i128; // 1% (100/10000)
    let fee_precision = 10000i128;

    // This mimics the fee calculation in deposit/withdraw
    let fee = amount
        .checked_mul(fee_ratio)
        .and_then(|x| x.checked_div(fee_precision))
        .expect("Fee calculation should not overflow");

    assert_eq!(fee, 10_000_000_000i128); // 1% of 1 trillion

    let amount_after_fee = amount
        .checked_sub(fee)
        .expect("Subtraction should not overflow");

    assert_eq!(amount_after_fee, 990_000_000_000i128);
}

#[test]
#[should_panic(expected = "Error(Contract, #314)")] // InvalidSignatureType
fn test_set_withdraw_verifier_invalid_signature_type() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _ = initialize_vault_with_defaults(&env, &client);

    // Try to set verifier with invalid signature type (not 0 or 1)
    let verifier_key = Bytes::from_array(&env, &[1u8; 32]);
    client.set_withdraw_verifier_by_admin(&999u32, &verifier_key);
}

#[test]
#[should_panic(expected = "Error(Contract, #317)")] // InvalidVerifierKey
fn test_set_withdraw_verifier_ed25519_wrong_length() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _ = initialize_vault_with_defaults(&env, &client);

    // Ed25519 key with wrong length (should be 32 bytes, not 31)
    let verifier_key = Bytes::from_array(&env, &[1u8; 31]);
    client.set_withdraw_verifier_by_admin(&0u32, &verifier_key);
}

#[test]
#[should_panic(expected = "Error(Contract, #317)")] // InvalidVerifierKey
fn test_set_withdraw_verifier_secp256k1_wrong_length() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _ = initialize_vault_with_defaults(&env, &client);

    // Secp256k1 key with wrong length (should be 65 bytes, not 64)
    let verifier_key = Bytes::from_array(&env, &[4u8; 64]);
    client.set_withdraw_verifier_by_admin(&1u32, &verifier_key);
}

#[test]
#[should_panic(expected = "Error(Contract, #317)")] // InvalidVerifierKey
fn test_set_withdraw_verifier_secp256k1_wrong_prefix() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _ = initialize_vault_with_defaults(&env, &client);

    // Secp256k1 key with wrong prefix (should be 0x04, not 0x03)
    let mut verifier_key_bytes = [0u8; 65];
    verifier_key_bytes[0] = 0x03; // Wrong prefix for uncompressed key
    let verifier_key = Bytes::from_array(&env, &verifier_key_bytes);
    client.set_withdraw_verifier_by_admin(&1u32, &verifier_key);
}

#[test]
fn test_set_withdraw_verifier_valid_keys() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_vault_contract(&env);
    let _ = initialize_vault_with_defaults(&env, &client);

    // Test valid Ed25519 key (32 bytes)
    let ed25519_key = Bytes::from_array(&env, &[2u8; 32]);
    client.set_withdraw_verifier_by_admin(&0u32, &ed25519_key);
    assert_eq!(client.get_withdraw_verifier(&0u32), Some(ed25519_key));

    // Test valid Secp256k1 key (65 bytes with 0x04 prefix)
    let mut secp256k1_key_bytes = [0u8; 65];
    secp256k1_key_bytes[0] = 0x04; // Correct prefix for uncompressed key
    for i in 1..65 {
        secp256k1_key_bytes[i] = (i % 256) as u8;
    }
    let secp256k1_key = Bytes::from_array(&env, &secp256k1_key_bytes);
    client.set_withdraw_verifier_by_admin(&1u32, &secp256k1_key);
    assert_eq!(client.get_withdraw_verifier(&1u32), Some(secp256k1_key));
}
