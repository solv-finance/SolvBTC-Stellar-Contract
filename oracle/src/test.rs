#![cfg(test)]
extern crate std;
use super::*;
use soroban_sdk::{
    testutils::Address as _,
    testutils::{MockAuth, MockAuthInvoke},
    Address, Env, IntoVal,
};
use std::println;

// Helper function to create contract and client
fn create_oracle_contract(env: &Env) -> (SolvBtcOracleClient, Address) {
    let contract_address = env.register(SolvBtcOracle, ());
    let client = SolvBtcOracleClient::new(env, &contract_address);
    (client, contract_address)
}

// ==================== Initialization Tests ====================

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 成功初始化
    client.initialize(&admin, &8, &1000000000, &500); // 8 decimal places, initial NAV=10, max change 5%

    // 验证初始化状态
    assert!(client.is_initialized());
    assert_eq!(client.admin(), admin);
    assert_eq!(client.get_nav(), 1000000000);
    assert_eq!(client.get_nav_decimals(), 8);
    assert_eq!(client.max_nav_change_percent(), 500);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_nav_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Try to use decimal places exceeding the maximum value
    client.initialize(&admin, &19, &1000000000, &500);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_initial_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Try to use negative NAV
    client.initialize(&admin, &8, &-1000000000, &500);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_max_change_percent() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Try to use maximum change percentage exceeding 100%
    client.initialize(&admin, &8, &1000000000, &10001);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_initialize_already_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // First initialization
    client.initialize(&admin, &8, &1000000000, &500);

    // Second initialization should fail
    client.initialize(&admin, &8, &2000000000, &1000);
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

// ==================== Admin Function Tests ====================

#[test]
fn test_set_nav_manager_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract
    client.initialize(&admin, &8, &1000000000, &500);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // Verify successful setting
    assert_eq!(client.nav_manager(), Some(nav_manager));
}

#[test]
fn test_set_max_nav_change_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract
    client.initialize(&admin, &8, &1000000000, &500);

    // Modify maximum change percentage
    client.set_max_nav_change_by_admin(&1000);

    // Verify successful modification
    assert_eq!(client.max_nav_change_percent(), 1000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_set_max_nav_change_invalid() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract
    client.initialize(&admin, &8, &1000000000, &500);

    // Try to set invalid maximum change percentage
    client.set_max_nav_change_by_admin(&10001);
}

// ==================== NAV Manager Function Tests ====================

#[test]
fn test_set_nav_by_manager_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract
    client.initialize(&admin, &8, &1000000000, &500);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // NAV manager sets new NAV value (4% change, within allowed range)
    client.set_nav_by_manager(&1040000000);

    // Verify successful setting
    assert_eq!(client.get_nav(), 1040000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_set_nav_by_manager_exceeds_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract (maximum change 5%)
    client.initialize(&admin, &8, &1000000000, &500);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // Try to set NAV value with change exceeding 5% (6% change)
    client.set_nav_by_manager(&1060000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #6)")]
fn test_set_nav_by_manager_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract but do not set NAV manager
    client.initialize(&admin, &8, &1000000000, &500);

    // Try to set NAV (should fail, because NAV manager is not set)
    client.set_nav_by_manager(&1040000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_set_nav_by_manager_invalid_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract
    client.initialize(&admin, &8, &1000000000, &500);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // Try to set negative NAV
    client.set_nav_by_manager(&-1000000000);
}

// ==================== Boundary Condition Tests ====================

#[test]
fn test_zero_max_change_percent() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract (maximum change 0%)
    client.initialize(&admin, &8, &1000000000, &0);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // Setting same NAV value should succeed
    client.set_nav_by_manager(&1000000000);

    assert_eq!(client.get_nav(), 1000000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_zero_max_change_percent_with_change() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract (maximum change 0%)
    client.initialize(&admin, &8, &1000000000, &0);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // Any change should fail
    client.set_nav_by_manager(&1000000001);
}

#[test]
fn test_maximum_nav_change() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract (maximum change 100%)
    client.initialize(&admin, &8, &1000000000, &10000);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // 100% change should succeed
    client.set_nav_by_manager(&2000000000);
    assert_eq!(client.get_nav(), 2000000000);

    // 100% change should succeed (from 20 to 10)
    client.set_nav_by_manager(&1000000000);
    assert_eq!(client.get_nav(), 1000000000);
}

// ==================== Precision Test ====================

#[test]
fn test_nav_change_precision() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract (maximum change 0.01%)
    client.initialize(&admin, &8, &1000000000, &1);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // 0.01% change should succeed
    client.set_nav_by_manager(&1000100000);
    assert_eq!(client.get_nav(), 1000100000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_nav_change_precision_exceeds() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // Initialize contract (maximum change 0.01%)
    client.initialize(&admin, &8, &1000000000, &1);

    // Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // 0.02% change should fail
    client.set_nav_by_manager(&1000200000);
}

// ==================== Boundary Value Tests ====================

#[test]
fn test_minimum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 0 decimal places should succeed
    client.initialize(&admin, &0, &10, &500);

    assert_eq!(client.get_nav_decimals(), 0);
}

#[test]
fn test_maximum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 18 decimal places should succeed
    client.initialize(&admin, &18, &1000000000000000000, &500);

    assert_eq!(client.get_nav_decimals(), 18);
}

// ==================== Comprehensive Test ====================

#[test]
fn test_complete_workflow() {
    let env = Env::default();
    env.mock_all_auths(); // Use simple global authorization simulation

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 1. Initialize contract
    client.initialize(&admin, &8, &1000000000, &500);

    // 2. Set NAV manager
    client.set_nav_manager_by_admin(&nav_manager);

    // 3. Update NAV value
    client.set_nav_by_manager(&1050000000);
    assert_eq!(client.get_nav(), 1050000000);

    // 4. Modify maximum change percentage
    client.set_max_nav_change_by_admin(&1000);
    assert_eq!(client.max_nav_change_percent(), 1000);

    // 5. Update NAV with new limit (10% change)
    client.set_nav_by_manager(&1155000000);
    assert_eq!(client.get_nav(), 1155000000);

    // 6. Verify all states
    assert!(client.is_initialized());
    assert_eq!(client.admin(), admin);
    assert_eq!(client.nav_manager(), Some(nav_manager));
    assert_eq!(client.get_nav_decimals(), 8);
}

// ==================== Basic Test ====================
#[test]
fn test_error_enum() {
    // Test error enum definition
    assert_eq!(OracleError::Unauthorized as u32, 1);
    assert_eq!(OracleError::InvalidArgument as u32, 2);
    assert_eq!(OracleError::NotInitialized as u32, 3);
    assert_eq!(OracleError::AlreadyInitialized as u32, 4);
    assert_eq!(OracleError::NavChangeExceedsLimit as u32, 5);
    assert_eq!(OracleError::NavManagerNotSet as u32, 6);
}
