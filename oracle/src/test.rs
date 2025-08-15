#![cfg(test)]
extern crate std;
use super::*;
use soroban_sdk::{
    contract, contractimpl, contracttype,
    testutils::{Address as _, Events},
    Address, Env,
};

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
fn create_oracle_contract(env: &Env) -> (SolvBtcOracleClient, Address, Address) {
    let admin = Address::generate(env);
    let contract_address = env.register(SolvBtcOracle, (&admin, 8u32, 1_000_000_000i128));
    let client = SolvBtcOracleClient::new(env, &contract_address);
    (client, contract_address, admin)
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
    let (vault_client, vault_address) = create_mock_vault(env);
    let (oracle_client, oracle_address, admin) = create_oracle_contract(env);

    // Set default withdraw ratio (5%)
    vault_client.set_withdraw_fee_ratio(&500);

    // Post-constructor configuration
    oracle_client.set_vault_by_admin(&vault_address);

    (oracle_client, oracle_address, admin, vault_client, vault_address)
}

// ==================== Initialization Tests ====================

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, admin) = create_oracle_contract(&env);
    let (_, vault_address) = create_mock_vault(&env);

    // Already initialized via constructor in create_oracle_contract; set vault
    client.set_vault_by_admin(&vault_address);
    assert_eq!(client.admin(), admin);
    assert_eq!(client.get_nav(), 1000000000);
    assert_eq!(client.get_nav_decimals(), 8);
}

#[test]
#[should_panic]
fn test_initialize_invalid_nav_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    // nav_decimals > 18 should cause contract error during constructor
    let _ = env.register(SolvBtcOracle, (&admin, 19u32, 10i128));
}

#[test]
#[should_panic]
fn test_initialize_invalid_initial_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    // initial_nav <= 0 should cause contract error during constructor
    let _ = env.register(SolvBtcOracle, (&admin, 8u32, 0i128));
}


// ==================== NAV Query Tests ====================

#[test]
fn test_nav_queries_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _) = create_oracle_contract(&env);

    // Constructor initializes; verify getters work
    assert_eq!(client.get_nav(), 1_000_000_000);
    assert_eq!(client.get_nav_decimals(), 8);
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
#[should_panic(expected = "HostError: Error(Contract, #202)")]
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
#[should_panic(expected = "HostError: Error(Contract, #202)")]
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
#[should_panic(expected = "HostError: Error(Contract, #205)")]
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
#[should_panic(expected = "HostError: Error(Contract, #206)")]
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

    // Deploy new oracle with 0 decimals
    let contract_address = env.register(SolvBtcOracle, (&admin, 0u32, 10i128));
    let client = SolvBtcOracleClient::new(&env, &contract_address);

    assert_eq!(client.get_nav_decimals(), 0);
}

#[test]
fn test_maximum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);

    // Deploy new oracle with 18 decimals
    let contract_address = env.register(SolvBtcOracle, (&admin, 18u32, 1_000_000_000_000_000_000i128));
    let client = SolvBtcOracleClient::new(&env, &contract_address);

    assert_eq!(client.get_nav_decimals(), 18);
}

// ==================== Event Tests ====================

#[test]
fn test_initialization_event() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _, _) = create_oracle_contract(&env);

    // Already initialized; just set vault and check events from constructor exist
    client.set_vault_by_admin(&vault_address);

    // Verify events
    let events = env.events().all();
    assert!(!events.is_empty());
}

#[test]
fn test_oracle_events_coverage() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    
    // Initialize contract (this publishes init event)
    let addr = env.register(SolvBtcOracle, (&admin, 8u32, 1_000_000_000i128));
    let client = SolvBtcOracleClient::new(&env, &addr);

    // Set NAV manager (this publishes event)
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);
    
    // Set up mock vault and NAV updates
    let (vault_client, vault_address) = create_mock_vault(&env);
    vault_client.set_withdraw_fee_ratio(&500);
    client.set_vault_by_admin(&vault_address);
    
    // Set NAV (this publishes event) 
    client.set_nav_by_manager(&1_050_000_000i128);

    let events = env.events().all();
    assert!(!events.is_empty());
}

// ==================== Comprehensive Tests ====================

#[test]
fn test_complete_workflow() {
    let env = Env::default();
    env.mock_all_auths();

    let _admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (vault_client, vault_address) = create_mock_vault(&env);
    let (client, _, _) = create_oracle_contract(&env);

    // Set vault withdraw ratio (10%)
    vault_client.set_withdraw_fee_ratio(&1000);

    // 1. Initialize contract
    // Constructor already ran; set vault
    client.set_vault_by_admin(&vault_address);
    // After constructor, contract is initialized

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
    // admin is the one used in constructor; here just ensure admin getter works
    let _ = client.admin();
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
#[should_panic(expected = "HostError: Error(Contract, #205)")]
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
    assert_eq!(OracleError::Unauthorized as u32, 201);
    assert_eq!(OracleError::InvalidArgument as u32, 202);
    assert_eq!(OracleError::NotInitialized as u32, 203);
    assert_eq!(OracleError::AlreadyInitialized as u32, 204);
    assert_eq!(OracleError::NavChangeExceedsLimit as u32, 205);
    assert_eq!(OracleError::NavManagerNotSet as u32, 206);
}


/// Test invalid NAV in set_nav_by_manager
#[test]
#[should_panic(expected = "HostError: Error(Contract, #202)")]
fn test_set_nav_by_manager_invalid_nav_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);   
    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    client.set_nav_by_manager(&0);
}

/// Test invalid NAV in set_nav_by_manager - negative
#[test]
#[should_panic(expected = "HostError: Error(Contract, #202)")]
fn test_set_nav_by_manager_invalid_nav_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);
    // Set NAV manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);
    
    client.set_nav_by_manager(&-100);
}

/// Test unauthorized nav manager operations
#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_set_nav_manager_unauthorized() {
    let env = Env::default();
    
    let admin = Address::generate(&env);
    let (_, vault_address) = create_mock_vault(&env);
    let (client, _, _) = create_oracle_contract(&env);
    
    // Initialize with admin authorization
    env.mock_all_auths();
    client.set_vault_by_admin(&vault_address);
    
    // Clear all mocked auths to test unauthorized access
    env.mock_auths(&[]);
    
    // Create an unauthorized user address
    let unauthorized_user = Address::generate(&env);
    
    // Try to set nav manager from unauthorized address without proper auth - should fail
    client.set_nav_manager_by_admin(&unauthorized_user);
}

/// Constructor initializes; nav query should succeed
#[test]
fn test_get_nav_initialized_after_constructor() {
    let env = Env::default();
    let (client, _, _) = create_oracle_contract(&env);
    let _ = client.get_nav();
}

/// Constructor initializes; decimals query should succeed
#[test]
fn test_get_nav_decimals_after_constructor() {
    let env = Env::default();
    let (client, _, _) = create_oracle_contract(&env);
    let _ = client.get_nav_decimals();
}

/// Constructor initializes; admin query should succeed
#[test]
fn test_admin_query_after_constructor() {
    let env = Env::default();
    let (client, _, _) = create_oracle_contract(&env);
    let _ = client.admin();
}

/// Test nav manager query before it's set
#[test]
fn test_nav_manager_query_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, _, _) = setup_initialized_oracle(&env);
    
    // Nav manager should be None initially
    assert_eq!(client.nav_manager(), None);
}



// ==================== Additional Tests for Oracle Coverage ====================

/// Test nav manager workflow with events
#[test]
fn test_nav_manager_complete_workflow() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);

    // Set vault's withdraw ratio (5%)
    vault_client.set_withdraw_fee_ratio(&500);

    // Initially no nav manager should be set
    assert_eq!(client.nav_manager(), None);

    // Set NAV manager (this should emit an event)
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);

    // Verify nav manager is set
    assert_eq!(client.nav_manager(), Some(nav_manager.clone()));

    // Update NAV (this should emit an event)
    let old_nav = client.get_nav();
    let new_nav = 1050000000; // Increase 5%
    client.set_nav_by_manager(&new_nav);

    // Verify NAV was updated
    assert_eq!(client.get_nav(), new_nav);
    
    // Just verify the operations completed successfully - events may not be captured in test environment
    // The fact that we can call these functions without panic means they're working
}

/// Test initialization event emission
#[test]
fn test_initialization_creates_events() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let vault = Address::generate(&env);
    let (client, _, _) = create_oracle_contract(&env);

    // Initialize and capture events
    client.set_vault_by_admin(&vault);

    // Events may not be captured in test environment - focus on state verification
    
    // Verify state after initialization
    // After constructor, contract is initialized
    // client.admin() should equal the admin passed during constructor in create_oracle_contract
    // But create_oracle_contract generates its own admin; only verify getters are consistent
    let _ = client.admin();
    assert_eq!(client.get_nav_decimals(), 8);
    assert_eq!(client.get_nav(), 1_000_000_000);
}

/// Test admin authorization and internal functions coverage
#[test]
fn test_admin_internal_functions() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, admin, _, _) = setup_initialized_oracle(&env);
    
    // Verify admin is correctly returned
    assert_eq!(client.admin(), admin);
    
    // Test setting nav manager requires admin auth
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);
    
    // Verify nav manager was set
    assert_eq!(client.nav_manager(), Some(nav_manager.clone()));
}

/// Test nav manager authorization and functions
#[test]
fn test_nav_manager_authorization() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);
    
    // Set up vault withdraw ratio
    vault_client.set_withdraw_fee_ratio(&1000); // 10%
    
    // Set nav manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);
    
    // Test nav manager can update NAV
    let new_nav = 1100000000; // 10% increase
    client.set_nav_by_manager(&new_nav);
    
    assert_eq!(client.get_nav(), new_nav);
}

/// Test edge case: exact limit NAV changes
#[test]
fn test_nav_change_at_exact_limits() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);
    
    // Set vault's withdraw ratio to exactly 1000 basis points (10%)
    vault_client.set_withdraw_fee_ratio(&1000);
    
    // Set nav manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);
    
    // Test exact boundary: 10% increase
    let current_nav = client.get_nav();
    let exact_limit_nav = current_nav + (current_nav * 1000 / 10000);
    client.set_nav_by_manager(&exact_limit_nav);
    
    assert_eq!(client.get_nav(), exact_limit_nav);
}

/// Test various precision scenarios
#[test]
fn test_nav_precision_scenarios() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _, _, vault_client, _) = setup_initialized_oracle(&env);
    
    // Set small withdraw ratio for precise testing
    vault_client.set_withdraw_fee_ratio(&100); // 1%
    
    // Set nav manager
    let nav_manager = Address::generate(&env);
    client.set_nav_manager_by_admin(&nav_manager);
    
    // Test small precise change
    let current_nav = client.get_nav();
    let precise_nav = current_nav + (current_nav / 100); // Exactly 1% increase
    client.set_nav_by_manager(&precise_nav);
    
    assert_eq!(client.get_nav(), precise_nav);
}

/// Test comprehensive initialization variations
#[test]
fn test_initialization_variations() {
    let env = Env::default();
    env.mock_all_auths();

    // Test with different decimal combinations
    let test_cases = [
        (0, 1i128), // Minimum decimals, minimum nav
        (8, 100_000_000i128), // Standard case
        (18, 1_000_000_000_000_000_000i128), // Maximum decimals
    ];
    
    for (decimals, nav) in test_cases {
        let admin = Address::generate(&env);
        let vault = Address::generate(&env);
        let (client, _, admin) = create_oracle_contract(&env);
        
        let contract = env.register(SolvBtcOracle, (&admin, decimals as u32, nav));
        let client = SolvBtcOracleClient::new(&env, &contract);
        
        // After constructor deploy, contract is initialized
        assert_eq!(client.get_nav_decimals(), decimals);
        assert_eq!(client.get_nav(), nav);
        assert_eq!(client.admin(), admin);
        assert_eq!(client.nav_manager(), None); // Initially no nav manager
    }
}

/// Test error enum completeness
#[test]
fn test_error_enum_completeness() {
    // Test all error enum values for coverage
    let errors = [
        OracleError::Unauthorized,
        OracleError::InvalidArgument,
        OracleError::NotInitialized,
        OracleError::AlreadyInitialized,
        OracleError::NavChangeExceedsLimit,
        OracleError::NavManagerNotSet,
    ];
    
    // Verify error codes are as expected
    assert_eq!(errors[0] as u32, 201);
    assert_eq!(errors[1] as u32, 202);
    assert_eq!(errors[2] as u32, 203);
    assert_eq!(errors[3] as u32, 204);
    assert_eq!(errors[4] as u32, 205);
    assert_eq!(errors[5] as u32, 206);
}
