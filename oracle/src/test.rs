#![cfg(test)]
extern crate std;
use super::*;
use soroban_sdk::{
    contract, contractimpl, contracttype,
    testutils::{Address as _, Events, MockAuth, MockAuthInvoke},
    Address, Env, Symbol,
};
use std::println;

// Mock Vault contract for testing
#[contract]
pub struct MockVault;

#[contracttype]
pub enum MockVaultDataKey {
    WithdrawFeeRatio,
}

#[contractimpl]
impl MockVault {
    /// Mock get_withdraw_fee_ratio function
    pub fn get_withdraw_fee_ratio(env: Env) -> i128 {
        // Return a default withdraw ratio of 5% (500 basis points)
        env.storage()
            .instance()
            .get(&MockVaultDataKey::WithdrawFeeRatio)
            .unwrap_or(500)
    }

    /// Set withdraw ratio for testing
    pub fn set_withdraw_fee_ratio(env: Env, ratio: i128) {
        env.storage()
            .instance()
            .set(&MockVaultDataKey::WithdrawFeeRatio, &ratio);
    }
}

// Helper functions
fn create_oracle_contract(env: &Env) -> (SolvBtcOracleClient, Address) {
    let contract_address = env.register(SolvBtcOracle, ());
    let client = SolvBtcOracleClient::new(env, &contract_address);
    (client, contract_address)
}

fn create_mock_vault(env: &Env) -> (MockVaultClient, Address) {
    let vault_address = env.register(MockVault, ());
    let vault_client = MockVaultClient::new(env, &vault_address);
    (vault_client, vault_address)
}

fn setup_initialized_oracle(
    env: &Env,
) -> (
    SolvBtcOracleClient,
    Address,
    Address,
    MockVaultClient,
    Address,
) {
    let admin = Address::generate(env);
    let (vault_client, vault_address) = create_mock_vault(env);
    let (oracle_client, oracle_address) = create_oracle_contract(env);

    // Set default withdraw ratio (5%)
    vault_client.set_withdraw_fee_ratio(&500);

    // Initialize oracle with vault
    oracle_client.initialize(&admin, &8, &1000000000, &vault_address);

    (
        oracle_client,
        oracle_address,
        admin,
        vault_client,
        vault_address,
    )
}

// ==================== Initialization Tests ====================

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // Successful initialization
    client.initialize(&admin, &8, &1000000000, &vault_address);

    // Verify initialization status
    assert!(client.is_initialized());
    assert_eq!(client.admin(), admin);
    assert_eq!(client.get_nav(), 1000000000);
    assert_eq!(client.get_nav_decimals(), 8);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_nav_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // Try to use decimal places exceeding maximum value
    client.initialize(&admin, &19, &1000000000, &vault_address);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_initial_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // Try to use negative NAV
    client.initialize(&admin, &8, &-1000000000, &vault_address);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_initialize_already_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // First initialization
    client.initialize(&admin, &8, &1000000000, &vault_address);

    // Second initialization should fail
    client.initialize(&admin, &8, &2000000000, &vault_address);
}

// ==================== NAV Query Tests ====================

#[test]
#[should_panic(expected = "HostError: Error(Contract, #3)")]
fn test_nav_queries_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _) = create_oracle_contract(&env);

    // Query should fail when not initialized
    client.get_nav();
}

#[test]
fn test_nav_queries_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);

    // Verify query functionality
    assert_eq!(client.get_nav(), 1000000000);
    assert_eq!(client.get_nav_decimals(), 8);
}

// ==================== Admin Functionality Tests ====================

#[test]
fn test_admin_functions() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, admin, _, _) = setup_initialized_oracle(&env);

    // Verify admin address
    assert_eq!(client.admin(), admin);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Verify setting successful
    assert_eq!(client.nav_manager(), Some(nav_manager));
}

// ==================== NAV Manager Functionality Tests ====================

#[test]
fn test_set_nav_by_manager_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (5%)
    vault_client.set_withdraw_fee_ratio(&500);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // NAV manager sets new NAV value (increase 4%, within allowed range)
    let new_nav = 1040000000; // Increase 4%
    client.set_nav_by_manager(&new_nav);

    // Verify setting successful
    assert_eq!(client.get_nav(), new_nav);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_set_nav_invalid_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Try to set negative NAV
    client.set_nav_by_manager(&-1000000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_set_nav_decreasing() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Try to set smaller NAV (should fail, according to new logic change < 0 will fail)
    client.set_nav_by_manager(&900000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_set_nav_exceeds_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (3%)
    vault_client.set_withdraw_fee_ratio(&300);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Try to set NAV value exceeding limit (increase 5%, exceeds 3% limit)
    client.set_nav_by_manager(&1050000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #6)")]
fn test_set_nav_manager_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);

    // Don't set NAV manager, directly try to set NAV
    client.set_nav_by_manager(&1050000000);
}

// ==================== Boundary Condition Tests ====================

#[test]
fn test_nav_change_at_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (5%)
    vault_client.set_withdraw_fee_ratio(&500);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Set NAV change exactly at the limit
    client.set_nav_by_manager(&1050000000); // Exactly 5% growth

    assert_eq!(client.get_nav(), 1050000000);
}

#[test]
fn test_zero_nav_change() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (0%)
    vault_client.set_withdraw_fee_ratio(&0);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Setting the same NAV value should succeed
    client.set_nav_by_manager(&1000000000);

    assert_eq!(client.get_nav(), 1000000000);
}

// ==================== Decimal Places Boundary Tests ====================

#[test]
fn test_minimum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // 0 decimal places should succeed
    client.initialize(&admin, &0, &10, &vault_address);

    assert_eq!(client.get_nav_decimals(), 0);
}

#[test]
fn test_maximum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // 18 decimal places should succeed
    client.initialize(&admin, &18, &1000000000000000000, &vault_address);

    assert_eq!(client.get_nav_decimals(), 18);
}

// ==================== Event Tests ====================

#[test]
fn test_initialization_event() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize and check events
    client.initialize(&admin, &8, &1000000000, &vault_address);

    // Verify events
    let events = env.events().all();
    assert!(!events.is_empty());
}

// ==================== Comprehensive Tests ====================

#[test]
fn test_complete_workflow() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (vault_client, vault_address) = create_mock_vault(&env);
    let (client, _) = create_oracle_contract(&env);

    // Set vault withdraw ratio (10%)
    vault_client.set_withdraw_fee_ratio(&1000);

    // 1. Initialize contract
    client.initialize(&admin, &8, &1000000000, &vault_address);
    assert!(client.is_initialized());

    // 2. Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);
    assert_eq!(client.nav_manager(), Some(nav_manager));

    // 3. Update NAV value
    client.set_nav_by_manager(&1100000000); // Increase 10%
    assert_eq!(client.get_nav(), 1100000000);

    // 4. Update NAV again
    client.set_nav_by_manager(&1210000000); // Increase 10% again
    assert_eq!(client.get_nav(), 1210000000);

    // 5. Verify all states
    assert_eq!(client.admin(), admin);
    assert_eq!(client.get_nav_decimals(), 8);
}

// ==================== Precision Tests ====================

#[test]
fn test_nav_change_precision() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (1%)
    vault_client.set_withdraw_fee_ratio(&100);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // 1% change should succeed
    client.set_nav_by_manager(&1010000000);
    assert_eq!(client.get_nav(), 1010000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_nav_change_precision_exceeds() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (1%)
    vault_client.set_withdraw_fee_ratio(&100);

    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // 2% change should fail
    client.set_nav_by_manager(&1020000000);
}

// ==================== Error Enum Tests ====================

#[test]
fn test_error_enum_values() {
    // Verify error enum definitions
    assert_eq!(OracleError::Unauthorized as u32, 1);
    assert_eq!(OracleError::InvalidArgument as u32, 2);
    assert_eq!(OracleError::NotInitialized as u32, 3);
    assert_eq!(OracleError::AlreadyInitialized as u32, 4);
    assert_eq!(OracleError::NavChangeExceedsLimit as u32, 5);
    assert_eq!(OracleError::NavManagerNotSet as u32, 6);
}
