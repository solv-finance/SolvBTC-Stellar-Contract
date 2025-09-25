use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, BytesN, Env,
    Symbol,
};
use stellar_default_impl_macro::default_impl;
use stellar_ownable::{self as ownable, Ownable};
use stellar_ownable_macro::only_owner;
use stellar_upgradeable::UpgradeableInternal;
use stellar_upgradeable_macros::Upgradeable;

use crate::dependencies::VaultClient;
pub use crate::traits::{NavAdminManagement, NavManagerManagement, NavQuery};

// ==================== Constants Definition ====================

/// Maximum NAV decimal places
const MAX_NAV_DECIMALS: u32 = 18;

// ==================== Error Type Definition ====================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum OracleError {
    // Invalid argument
    InvalidArgument = 201,
    // NAV change exceeds maximum allowed range
    NavChangeExceedsLimit = 202,
    // NAV manager not set
    NavManagerNotSet = 203,
    // Insufficient permissions
    Unauthorized = 204,
}

// ==================== Data Key Definition ====================

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
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

#[derive(Upgradeable)]
#[contract]
pub struct SolvBtcOracle;

// ==================== Constructor ====================

#[contractimpl]
impl SolvBtcOracle {
    pub fn __constructor(env: &Env, admin: Address, nav_decimals: u32, initial_nav: i128) {
        // Validate parameters
        if initial_nav <= 0 {
            panic_with_error!(env, OracleError::InvalidArgument);
        }

        if nav_decimals > MAX_NAV_DECIMALS {
            panic_with_error!(env, OracleError::InvalidArgument);
        }

        // Set owner using stellar-ownable
        ownable::set_owner(env, &admin);

        // Set initial data
        env.storage()
            .instance()
            .set(&DataKey::NavDecimals, &nav_decimals);
        env.storage().instance().set(&DataKey::Nav, &initial_nav);

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
        env.storage().instance().get(&DataKey::Nav).unwrap()
    }

    /// Get NAV decimal places
    fn get_nav_decimals(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::NavDecimals).unwrap()
    }

    /// Get the current admin address
    fn get_admin(env: Env) -> Address {
        // Use the ownable trait to get owner
        // ownable::get_owner returns Option<Address>, unwrap it
        Self::get_admin_internal(&env)
    }
}

#[contractimpl]
impl NavAdminManagement for SolvBtcOracle {
    /// Set NAV manager (admin only)
    #[only_owner]
    fn set_nav_manager_by_admin(env: Env, manager_address: Address) {
        env.storage()
            .instance()
            .set(&DataKey::NavManager, &manager_address);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_nav_manager"),),
            (Self::get_admin_internal(&env), manager_address.clone()),
        );
    }

    /// Set Vault address (admin only)
    #[only_owner]
    fn set_vault_by_admin(env: Env, vault: Address) {
        env.storage().instance().set(&DataKey::Vault, &vault);

        env.events().publish(
            (Symbol::new(&env, "set_vault"),),
            (Self::get_admin_internal(&env), vault.clone()),
        );
    }
}

#[contractimpl]
impl NavManagerManagement for SolvBtcOracle {
    /// Get NAV manager address
    fn get_nav_manager(env: Env) -> Address {
        Self::get_nav_manager_internal(&env)
    }

    /// Set NAV value (NAV manager only)
    fn set_nav_by_manager(env: Env, nav: i128) {
        let nav_manager: Address = Self::require_nav_manager(&env);

        if nav <= 0 {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }
        //Check new nav only increase or equal prev NAV ( >=)
        let current_nav: i128 = env.storage().instance().get(&DataKey::Nav).unwrap();

        //The growth rate between the set NAV and the previous NAV must not exceed the Vault’s withdraw fee rate
        let vault: Address = env.storage().instance().get(&DataKey::Vault).unwrap();
        //Get vault withdraw fee rate
        let withdraw_fee_rate: i128 = VaultClient::new(&env, &vault).get_withdraw_fee_ratio();

        // Check if NAV change exceeds limit
        Self::check_nav_change(&env, current_nav, nav, withdraw_fee_rate);

        // Update NAV value
        env.storage().instance().set(&DataKey::Nav, &nav);

        // Publish event
        env.events().publish(
            (Symbol::new(&env, "set_nav"),),
            (nav_manager, current_nav, nav),
        );
    }
}

// ==================== Internal Helper Functions ====================

impl SolvBtcOracle {
    /// Get admin address (internal helper)
    fn get_admin_internal(env: &Env) -> Address {
        ownable::get_owner(env).unwrap()
    }

    /// Get NAV manager address
    fn get_nav_manager_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::NavManager)
            .unwrap_or_else(|| panic_with_error!(env, OracleError::NavManagerNotSet))
    }

    /// Verify NAV manager permission
    fn require_nav_manager(env: &Env) -> Address {
        let nav_manager = Self::get_nav_manager_internal(env);
        nav_manager.require_auth();
        nav_manager
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

// ==================== Ownable Implementation ====================

#[default_impl]
#[contractimpl]
impl Ownable for SolvBtcOracle {}

impl UpgradeableInternal for SolvBtcOracle {
    fn _require_auth(e: &Env, operator: &Address) {
        operator.require_auth();
        let owner = ownable::get_owner(e).unwrap();
        if *operator != owner {
            panic_with_error!(e, OracleError::Unauthorized); // reuse existing error space
        }
    }
}
