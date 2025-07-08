use soroban_sdk::{
    contract, contracterror, contractimpl, contractmeta, contracttype, log, panic_with_error,
    symbol_short, Address, Env,
};

pub use crate::traits::{
    AdminManagement, NavManagerManagement, NavQuery, OracleEvents, OracleInitialization,
};

// ==================== Constants Definition ====================

/// Percentage precision constant (1/10000, i.e., 10000 = 100%)
const PERCENTAGE_PRECISION: u32 = 10000;

/// Maximum NAV decimal places
const MAX_NAV_DECIMALS: u32 = 18;

// Contract metadata
contractmeta!(
    key = "Description",
    val = "SolvBTC Oracle Contract for managing NAV (Net Asset Value)"
);

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
    // Maximum NAV change percentage (supports 1/10000, i.e., PERCENTAGE_PRECISION = 100%)
    MaxNavChangePercent,
}

// ==================== Contract Definition ====================

#[contract]
pub struct SolvBtcOracle;

// ==================== Contract Implementation ====================

#[contractimpl]
impl OracleInitialization for SolvBtcOracle {
    /// Initialize contract
    fn initialize(
        env: Env,
        admin: Address,
        nav_decimals: u32,
        initial_nav: i128,
        max_change_percent: u32,
    ) {
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

        if max_change_percent > PERCENTAGE_PRECISION {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }

        // Set initial data
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::NavDecimals, &nav_decimals);
        env.storage().instance().set(&DataKey::Nav, &initial_nav);
        env.storage()
            .instance()
            .set(&DataKey::MaxNavChangePercent, &max_change_percent);
        env.storage().instance().set(&DataKey::Initialized, &true);

        // Publish initialization event
        env.events().publish(
            (symbol_short!("init"),),
            (admin.clone(), initial_nav, nav_decimals, max_change_percent),
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

    /// Get maximum NAV change percentage
    fn max_nav_change_percent(env: Env) -> u32 {
        Self::require_initialized(&env);
        env.storage()
            .instance()
            .get(&DataKey::MaxNavChangePercent)
            .unwrap()
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
            (symbol_short!("nav_mgr"),),
            (Self::get_admin(&env), manager_address.clone()),
        );
    }

    /// Set maximum NAV change percentage (admin only)
    fn set_max_nav_change_by_admin(env: Env, max_change_percent: u32) {
        Self::require_admin(&env);

        if max_change_percent > PERCENTAGE_PRECISION {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }

        env.storage()
            .instance()
            .set(&DataKey::MaxNavChangePercent, &max_change_percent);

        // Publish event
        env.events().publish(
            (symbol_short!("max_chg"),),
            (Self::get_admin(&env), max_change_percent),
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
        log!(&env, "nav_manager2: {:?}", nav_manager);
        nav_manager.require_auth();
        log!(&env, "nav_decimals3: {:?}", 11131313);

        if nav <= 0 {
            panic_with_error!(&env, OracleError::InvalidArgument);
        }

        let current_nav: i128 = env.storage().instance().get(&DataKey::Nav).unwrap();
        let max_change_percent: u32 = env
            .storage()
            .instance()
            .get(&DataKey::MaxNavChangePercent)
            .unwrap();

        // Calculate percentage change based on precision
        let nav_decimals: u32 = env.storage().instance().get(&DataKey::NavDecimals).unwrap();
        // Check if NAV change exceeds limit
        Self::check_nav_change(&env, current_nav, nav, max_change_percent, nav_decimals);

        // Update NAV value
        env.storage().instance().set(&DataKey::Nav, &nav);

        // Publish event
        env.events().publish(
            (symbol_short!("nav_set"),),
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
            (symbol_short!("init"),),
            (admin.clone(), initial_nav, nav_decimals, max_change_percent),
        );
    }

    /// Publish NAV manager set event   
    fn emit_nav_manager_set_event(env: Env, admin: Address, nav_manager: Address) {
        env.events().publish(
            (symbol_short!("nav_mgr"),),
            (admin.clone(), nav_manager.clone()),
        );
    }

    /// Publish maximum change percentage update event
    fn emit_max_change_updated_event(env: Env, admin: Address, max_change_percent: u32) {
        env.events().publish(
            (symbol_short!("max_chg"),),
            (admin.clone(), max_change_percent),
        );
    }

    /// Publish NAV value update event
    fn emit_nav_updated_event(env: Env, nav_manager: Address, old_nav: i128, new_nav: i128) {
        env.events().publish(
            (symbol_short!("nav_set"),),
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
            Some(nav_manager) => {
                log!(&env, "nav_manager_opt: {:?}", nav_manager);
                nav_manager
            }
            None => {
                panic_with_error!(env, OracleError::NavManagerNotSet);
            }
        }
    }

    /// Validate if NAV change is within allowed range based on precision (internal function)
    fn check_nav_change(
        env: &Env,
        current_nav: i128,
        new_nav: i128,
        max_change_percent: u32,
        nav_decimals: u32,
    ) {
        if max_change_percent == 0 {
            // If maximum change percentage is 0, no change is allowed
            if current_nav != new_nav {
                panic_with_error!(env, OracleError::NavChangeExceedsLimit);
            }
            return;
        }

        // Calculate percentage change (in units of 1/10000)
        let change = if new_nav > current_nav {
            new_nav - current_nav
        } else {
            current_nav - new_nav
        };

        // Calculate change percentage: (change * PERCENTAGE_PRECISION) / current_nav
        let change_percent = (change * PERCENTAGE_PRECISION as i128) / current_nav;

        if change_percent > max_change_percent as i128 {
            panic_with_error!(env, OracleError::NavChangeExceedsLimit);
        }
    }
}
