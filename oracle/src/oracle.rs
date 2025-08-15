use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Env, Symbol,
};

pub use crate::traits::{
    AdminManagement, NavManagerManagement, NavQuery,
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
    Unauthorized = 201,
    // Invalid argument
    InvalidArgument = 202,
    // Contract not initialized
    NotInitialized = 203,
    // Contract already initialized
    AlreadyInitialized = 204,
    // NAV change exceeds maximum allowed range
    NavChangeExceedsLimit = 205,
    // NAV manager not set
    NavManagerNotSet = 206,
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

// ==================== Constructor ====================

#[contractimpl]
impl SolvBtcOracle {
    pub fn __constructor(env: &Env, admin: Address, nav_decimals: u32, initial_nav: i128) {
        // Check if already initialized
        if Self::check_initialized(env) {
            panic_with_error!(env, OracleError::AlreadyInitialized);
        }

        // Validate parameters
        if initial_nav <= 0 {
            panic_with_error!(env, OracleError::InvalidArgument);
        }

        if nav_decimals > MAX_NAV_DECIMALS {
            panic_with_error!(env, OracleError::InvalidArgument);
        }

        // Set initial data
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::NavDecimals, &nav_decimals);
        env.storage().instance().set(&DataKey::Nav, &initial_nav);
        env.storage().instance().set(&DataKey::Initialized, &true);

        // Publish initialization event
        env.events().publish(
            (Symbol::new(env, "initialize"),),
            (admin.clone(), initial_nav, nav_decimals),
        );
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

    /// Set Vault address (admin only)
    fn set_vault_by_admin(env: Env, vault: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Vault, &vault);

        env.events().publish(
            (Symbol::new(&env, "set_vault"), vault.clone()),
            (Self::get_admin(&env)),
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
