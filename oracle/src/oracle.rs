use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Env, Symbol,
};

pub use crate::traits::{
    AdminManagement, NavManagerManagement, NavQuery, OracleEvents, OracleInitialization,
};

use crate::dependencies::VaultClient;

// ==================== Constants Definition ====================

/// Maximum NAV decimal places
const MAX_NAV_DECIMALS: u32 = 18;


// ==================== Error Type Definition ====================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum OracleError {
    // Insufficient permissions
    Unauthorized = 1,
    // Invalid argument
    InvalidArgument = 2,
    // Contract not initialized
    NotInitialized = 3,
    // Contract already initialized
    AlreadyInitialized = 4,
    // NAV change exceeds maximum allowed range
    NavChangeExceedsLimit = 5,
    // NAV manager not set
    NavManagerNotSet = 6,
}

// ==================== Data Key Definition ====================

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    // Contract admin
    Admin,
    // Initialization status
    Initialized,
    // Current NAV value (with decimal places)
    Nav,
    // NAV decimal places
    NavDecimals,
    // NAV manager address
    NavManager,
    // Vault contract address
    Vault,
}

// ==================== Contract Definition ====================

#[contract]
pub struct SolvBtcOracle;

// ==================== Contract Implementation ====================

#[contractimpl]
impl OracleInitialization for SolvBtcOracle {
    /// Initialize contract
    fn initialize(env: Env, admin: Address, nav_decimals: u32, initial_nav: i128, vault: Address) {
        // Verify admin permissions
        admin.require_auth();

        // Check if already initialized
        if Self::check_initialized(&env) {
            panic_with_error!(&env, OracleError::AlreadyInitialized);
        }

        // Validate parameters
        if initial_nav <= 0 {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }

        if nav_decimals > MAX_NAV_DECIMALS {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }

        // Set initial data
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::NavDecimals, &nav_decimals);
        env.storage().instance().set(&DataKey::Nav, &initial_nav);
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::Vault, &vault);
        // Publish initialization event
        env.events().publish(
            (Symbol::new(&env, "init"),),
            (admin.clone(), initial_nav, nav_decimals, vault.clone()),
        );
    }

    /// Check if contract is initialized
    fn is_initialized(env: Env) -> bool {
        Self::check_initialized(&env)
    }
}

#[contractimpl]
impl NavQuery for SolvBtcOracle {
    /// Get current NAV value
    fn get_nav(env: Env) -> i128 {
        Self::require_initialized(&env);
        env.storage().instance().get(&DataKey::Nav).unwrap()
    }

    /// Get NAV decimal places
    fn get_nav_decimals(env: Env) -> u32 {
        Self::require_initialized(&env);
        env.storage().instance().get(&DataKey::NavDecimals).unwrap()
    }
}

#[contractimpl]
impl AdminManagement for SolvBtcOracle {
    /// Get admin address
    fn admin(env: Env) -> Address {
        Self::require_initialized(&env);
        Self::get_admin(&env)
    }

    /// Set NAV manager (admin only)
    fn set_nav_manager_by_admin(env: Env, manager_address: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::NavManager, &manager_address);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_nav_manager"),),
            (Self::get_admin(&env), manager_address.clone()),
        );
    }
}

#[contractimpl]
impl NavManagerManagement for SolvBtcOracle {
    /// Get NAV manager address
    fn nav_manager(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::NavManager)
    }

    /// Set NAV value (NAV manager only)
    fn set_nav_by_manager(env: Env, nav: i128) {
        let nav_manager: Address = Self::require_nav_manager(&env);
        nav_manager.require_auth();

        if nav <= 0 {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }
        //Check new nav only increase or equal prev NAV ( >=)
        let current_nav: i128 = env.storage().instance().get(&DataKey::Nav).unwrap();

        //The growth rate between the set NAV and the previous NAV must not exceed the Vault’s withdraw fee rate
        //Get vault withdraw fee rate
        let vault: Address = env.storage().instance().get(&DataKey::Vault).unwrap();

        let withdraw_fee_rate: i128 = VaultClient::new(&env, &vault).get_withdraw_fee_ratio();

        // Calculate percentage change based on precision
        let nav_decimals: u32 = env.storage().instance().get(&DataKey::NavDecimals).unwrap();
        // Check if NAV change exceeds limit
        Self::check_nav_change(&env, current_nav, nav, withdraw_fee_rate);

        // Update NAV value
        env.storage().instance().set(&DataKey::Nav, &nav);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_nav"),),
            (Self::get_nav_manager(&env), current_nav, nav),
        );
    }
}

// ==================== Additional Trait Implementations ====================

#[contractimpl]
impl OracleEvents for SolvBtcOracle {
    /// Publish initialization event
    fn emit_initialization_event(
        env: Env,
        admin: Address,
        initial_nav: i128,
        nav_decimals: u32,
        max_change_percent: u32,
    ) {
        env.events().publish(
            (Symbol::new(&env, "init"),),
            (admin.clone(), initial_nav, nav_decimals, max_change_percent),
        );
    }

    /// Publish NAV manager set event   
    fn emit_nav_manager_set_event(env: Env, admin: Address, nav_manager: Address) {
        env.events().publish(
            (Symbol::new(&env, "set_nav_manager"),),
            (admin.clone(), nav_manager.clone()),
        );
    }

    /// Publish maximum change percentage update event
    fn emit_max_change_updated_event(env: Env, admin: Address, max_change_percent: u32) {
        env.events().publish(
            (Symbol::new(&env, "set_max_nav_change"),),
            (admin.clone(), max_change_percent),
        );
    }

    /// Publish NAV value update event
    fn emit_nav_updated_event(env: Env, nav_manager: Address, old_nav: i128, new_nav: i128) {
        env.events().publish(
            (Symbol::new(&env, "set_nav"),),
            (nav_manager.clone(), old_nav, new_nav),
        );
    }
}

// ==================== Internal Helper Functions ====================

impl SolvBtcOracle {
    /// Check if contract is initialized (internal function)
    fn check_initialized(env: &Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    /// Require contract to be initialized
    fn require_initialized(env: &Env) {
        if !Self::check_initialized(env) {
            panic_with_error!(env, OracleError::NotInitialized);
        }
    }

    /// Get admin address
    fn get_admin(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Get NAV manager address
    fn get_nav_manager(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::NavManager).unwrap()
    }

    /// Verify admin permission
    fn require_admin(env: &Env) -> Address {
        Self::require_initialized(env);
        let admin = Self::get_admin(env);
        admin.require_auth();
        admin
    }

    /// Verify NAV manager permission
    fn require_nav_manager(env: &Env) -> Address {
        let nav_manager_opt: Option<Address> = env.storage().instance().get(&DataKey::NavManager);
        match nav_manager_opt {
            Some(nav_manager) => nav_manager,
            None => {
                panic_with_error!(env, OracleError::NavManagerNotSet);
            }
        }
    }

    /// Validate if NAV change is within allowed range based on precision (internal function)
    fn check_nav_change(env: &Env, current_nav: i128, new_nav: i128, withdraw_fee_rate: i128) {
        // Calculate change increase or equal prev NAV
        let change = new_nav - current_nav;
        if change < 0 {
            panic_with_error!(env, OracleError::InvalidArgument);
        }
        // The growth rate between the set NAV and the previous NAV must not exceed the Vault’s withdraw fee rate
        let change_percent = change * 10000 / current_nav;

        if change_percent > withdraw_fee_rate {
            panic_with_error!(env, OracleError::NavChangeExceedsLimit);
        }
    }
}
