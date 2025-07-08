#![cfg(test)]
extern crate std;
use super::*;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use soroban_sdk::{log, testutils::Address as _, Address, Bytes, Env, String};

// Helper functions for creating contract and client
fn create_vault_contract(env: &Env) -> (SolvBTCVaultClient, Address) {
    let contract_address = env.register(SolvBTCVault, ());
    let client = SolvBTCVaultClient::new(env, &contract_address);
    (client, contract_address)
}

// Helper function: Create real Ed25519 public key address
fn create_mock_public_key(env: &Env) -> Address {
    // Use a valid Stellar account address string
    let stellar_address = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

    // Create Address object from string
    Address::from_str(env, stellar_address)
}

// Helper function: Create mock Ed25519 signature (64 bytes)
fn create_mock_signature(env: &Env) -> Bytes {
    let mut signature_bytes = [0u8; 64];
    // Fill with some test data
    for i in 0..64 {
        signature_bytes[i] = (i % 256) as u8;
    }
    Bytes::from_array(env, &signature_bytes)
}

// Helper function: Create request hash
fn create_request_hash(env: &Env, nonce: u64) -> Bytes {
    let mut hash_bytes = [0u8; 32];
    // Simply write nonce to first 8 bytes
    let nonce_bytes = nonce.to_be_bytes();
    hash_bytes[..8].copy_from_slice(&nonce_bytes);
    Bytes::from_array(env, &hash_bytes)
}

// ==================== EIP712 Related Tests ====================

#[test]
fn test_eip712_domain_separator_generation() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );

    // Test EIP712 related queries
    let domain_name = client.get_eip712_domain_name();
    let domain_version = client.get_eip712_domain_version();
    let chain_id = client.get_eip712_chain_id();
    let domain_separator = client.get_eip712_domain_separator();
    log!(&env, "domain_separator: {:?}", domain_separator);

    // Verify return values are not empty
    assert!(domain_name.len() > 0);
    assert!(domain_version.len() > 0);
    assert_eq!(chain_id.len(), 32); // network_id is 32 bytes
    assert_eq!(domain_separator.len(), 32); // SHA256 hash is 32 bytes
}

#[test]
fn test_eip712_domain_management() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );

    // Get initial values
    let initial_name = client.get_eip712_domain_name();
    let initial_version = client.get_eip712_domain_version();
    let initial_separator = client.get_eip712_domain_separator();

    // Update EIP712 domain parameters
    let new_name = soroban_sdk::String::from_str(&env, "Updated withdraw");
    let new_version = soroban_sdk::String::from_str(&env, "2.0");
    client.set_eip712_domain_by_admin(&new_name, &new_version);

    // Verify parameters have been updated
    let updated_name = client.get_eip712_domain_name();
    let updated_version = client.get_eip712_domain_version();
    let updated_separator = client.get_eip712_domain_separator();

    assert_ne!(initial_name, updated_name);
    assert_ne!(initial_version, updated_version);

    // Domain separator should also update when name and version change
    assert_ne!(initial_separator, updated_separator);
}

#[test]
fn test_withdraw_verifier_key_management() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let initial_verifier_pubkey = create_mock_public_key(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &initial_verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );

    // Verify initial verifier public key
    assert_eq!(client.get_withdraw_verifier(), initial_verifier_pubkey);

    let updated_verifier_pubkey = Address::generate(&env);

    client.set_withdraw_verifier_by_admin(&updated_verifier_pubkey);

    // Verify verifier public key has been updated
    assert_eq!(client.get_withdraw_verifier(), updated_verifier_pubkey);
    assert_ne!(client.get_withdraw_verifier(), initial_verifier_pubkey);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #23)")] // InvalidSignatureFormat
fn test_withdraw_invalid_signature_length() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);
    let user = Address::generate(&env);
    let currency = Address::generate(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );
    client.add_currency_by_admin(&currency);
    client.set_withdraw_currency_by_admin(&currency);

    // Create signature with invalid length (should be 64 bytes)
    let invalid_signature = Bytes::from_array(&env, &[1u8; 32]); // Only 32 bytes

    let target_amount = 1000i128;
    let nav = 50000i128;
    let request_hash = create_request_hash(&env, 1);
    let timestamp = 1700000000u64;

    // Should fail due to invalid signature length
    client.withdraw(
        &user,
        &target_amount,
        &nav,
        &request_hash,
        &timestamp,
        &invalid_signature,
    );
}

#[test]
fn test_eip712_message_construction() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );

    // Test internal message construction (using contract client)
    let domain_separator = client.get_eip712_domain_separator();

    // Verify domain separator is not empty
    assert_eq!(domain_separator.len(), 32);
}

#[test]
fn test_basic_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );

    // Verify initialization
    assert!(client.is_initialized());
    assert_eq!(client.admin(), admin);
    assert_eq!(client.get_minter_manager(), minter_manager);
    assert_eq!(client.get_oracle(), oracle);
    assert_eq!(client.get_treasurer(), treasurer);
    assert_eq!(client.get_withdraw_verifier(), verifier_pubkey);
    assert_eq!(client.get_withdraw_ratio(), 100);
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

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);
    let user = Address::generate(&env);
    let currency = Address::generate(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );

    // Add currency
    client.add_currency_by_admin(&currency);
    client.set_withdraw_currency_by_admin(&currency);

    // Create valid parameters
    let target_amount = 1000i128;
    let nav = 50000i128;
    let request_hash = create_request_hash(&env, 1);
    let timestamp = 1700000000u64;
    let signature = create_mock_signature(&env);

    // Verify parameter formats
    assert!(target_amount > 0);
    assert!(nav > 0);
    assert_eq!(request_hash.len(), 32);
    assert_eq!(timestamp > 0, true);
    assert_eq!(signature.len(), 64);

    // Verify contract state
    assert_eq!(client.get_withdraw_currency().unwrap(), currency);
    assert!(client.is_currency_supported(&currency));
}

#[test]
fn test_mock_public_key_format() {
    let env = Env::default();

    // Create mock public key
    let pubkey = create_mock_public_key(&env);

    // Verify it's a valid Address
    assert!(pubkey.to_xdr(&env).len() > 0);
}

#[test]
#[should_panic(expected = "HostError: Error(Crypto, InvalidInput)")] // Crypto error from invalid signature
fn test_withdraw_with_mock_pubkey() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let oracle = Address::generate(&env);
    let treasurer = Address::generate(&env);
    let verifier_pubkey = create_mock_public_key(&env);
    let user = Address::generate(&env);
    let currency = Address::generate(&env);

    let (client, _) = create_vault_contract(&env);

    // Initialize contract
    let domain_name = soroban_sdk::String::from_str(&env, "withdraw");
    let domain_version = soroban_sdk::String::from_str(&env, "1");
    client.initialize(
        &admin,
        &minter_manager,
        &token_contract,
        &oracle,
        &treasurer,
        &verifier_pubkey,
        &100,
        &domain_name,
        &domain_version,
    );
    client.add_currency_by_admin(&currency);
    client.set_withdraw_currency_by_admin(&currency);

    // Create valid parameters but with mock signature
    let target_amount = 1000i128;
    let nav = 50000i128;
    let request_hash = create_request_hash(&env, 1);
    let timestamp = 1700000000u64;
    let signature = create_mock_signature(&env);

    // Should fail due to invalid signature (not properly signed)
    client.withdraw(
        &user,
        &target_amount,
        &nav,
        &request_hash,
        &timestamp,
        &signature,
    );
}

// ==================== Basic Tests ====================

#[test]
fn test_constants() {
    // Verify constants
    assert_eq!(MAX_CURRENCIES, 10);
    assert_eq!(FEE_PRECISION, 10000);
}

#[test]
fn test_error_enum() {
    // Verify error codes
    assert_eq!(VaultError::Unauthorized as u32, 1);
    assert_eq!(VaultError::InvalidArgument as u32, 2);
    assert_eq!(VaultError::NotInitialized as u32, 3);
    assert_eq!(VaultError::AlreadyInitialized as u32, 4);
    assert_eq!(VaultError::CurrencyNotSupported as u32, 5);
    assert_eq!(VaultError::TooManyCurrencies as u32, 6);
    assert_eq!(VaultError::CurrencyAlreadyExists as u32, 7);
    assert_eq!(VaultError::CurrencyNotExists as u32, 8);
    assert_eq!(VaultError::InvalidAmount as u32, 9);
    assert_eq!(VaultError::OracleNotSet as u32, 10);
    assert_eq!(VaultError::MinterManagerNotSet as u32, 11);
    assert_eq!(VaultError::TreasurerNotSet as u32, 12);
    assert_eq!(VaultError::WithdrawVerifierNotSet as u32, 13);
    assert_eq!(VaultError::WithdrawCurrencyNotSet as u32, 14);
    assert_eq!(VaultError::InvalidSignature as u32, 15);
    assert_eq!(VaultError::RequestHashAlreadyUsed as u32, 16);
    assert_eq!(VaultError::InvalidNav as u32, 17);
    assert_eq!(VaultError::InvalidWithdrawRatio as u32, 18);
    assert_eq!(VaultError::InvalidSignatureFormat as u32, 23);
}
