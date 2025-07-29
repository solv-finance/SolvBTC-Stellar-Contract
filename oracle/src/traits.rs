use soroban_sdk::{contractclient, Address, Env};

/// Oracle initialization trait
/// Responsible for contract initialization and state checking
pub trait OracleInitialization {
    /// Initialize Oracle contract
    ///
    /// # Parameters
    /// - `admin`: Admin address
    /// - `nav_decimals`: NAV decimal places
    /// - `initial_nav`: Initial NAV value
    /// - `max_change_bps`: Maximum NAV change in basis points (10000 = 100%)
    fn initialize(env: Env, admin: Address, nav_decimals: u32, initial_nav: i128, vault: Address);

    /// Check if contract is initialized
    fn is_initialized(env: Env) -> bool;
}

#[contractclient(name = "OracleClient")]
/// Oracle NAV management trait
/// Responsible for NAV-related data queries
pub trait NavQuery {
    /// Get current NAV value
    fn get_nav(env: Env) -> i128;

    /// Get NAV decimal places
    fn get_nav_decimals(env: Env) -> u32;
}

/// Admin management trait
/// Responsible for admin-related functions
pub trait AdminManagement {
    /// Get admin address
    fn admin(env: Env) -> Address;

    /// Set NAV manager by admin
    fn set_nav_manager_by_admin(env: Env, manager_address: Address);
}

/// NAV manager management trait
/// Responsible for NAV manager functions
pub trait NavManagerManagement {
    /// Get NAV manager address
    fn nav_manager(env: Env) -> Option<Address>;

    /// Set NAV by manager
    fn set_nav_by_manager(env: Env, nav: i128);
}

/// Oracle event trait
/// Defines contract event-related functions
pub trait OracleEvents {
    /// Emit initialization event
    fn emit_initialization_event(
        env: Env,
        admin: Address,
        initial_nav: i128,
        nav_decimals: u32,
        max_change_percent: u32,
    );

    /// Emit NAV manager set event
    fn emit_nav_manager_set_event(env: Env, admin: Address, nav_manager: Address);

    /// Emit max change percent updated event
    fn emit_max_change_updated_event(env: Env, admin: Address, max_change_percent: u32);

    /// Emit NAV value updated event
    fn emit_nav_updated_event(env: Env, nav_manager: Address, old_nav: i128, new_nav: i128);
}
