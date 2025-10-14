use soroban_sdk::{contractclient, Address, Env};

// Removed OracleInitialization trait; constructor is used instead

#[contractclient(name = "OracleClient")]
/// Oracle NAV management trait
/// Responsible for NAV-related data queries
pub trait NavQuery {
    /// Get current NAV value
    fn get_nav(env: Env) -> i128;

    /// Get NAV decimal places
    fn get_nav_decimals(env: Env) -> u32;

    /// Get the current admin address
    fn get_admin(env: Env) -> Address;

    /// Get the last updated timestamp
    fn get_last_updated_at(env: Env) -> u64;
}

/// Admin management trait
/// Responsible for admin-related functions
pub trait NavAdminManagement {
    /// Set NAV manager by admin
    fn set_nav_manager_by_admin(env: Env, manager_address: Address);

    /// Set Vault address by admin
    fn set_vault_by_admin(env: Env, vault: Address);
}

/// NAV manager management trait
/// Responsible for NAV manager functions
pub trait NavManagerManagement {
    /// Get NAV manager address
    fn get_nav_manager(env: Env) -> Address;

    /// Set NAV by manager
    fn set_nav_by_manager(env: Env, nav: i128);
}
