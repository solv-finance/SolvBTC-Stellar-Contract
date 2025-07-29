use soroban_sdk::{contractclient, Address, Env, Vec};

// ==================== Trait Definitions ====================

/// Initialization trait
pub trait InitializableTrait {
    fn initialize(env: Env, admin: Address, token_contract: Address);
    fn is_initialized(env: Env) -> bool;
}

/// Admin management trait
pub trait AdminTrait {
    fn admin(env: Env) -> Address;
    fn transfer_admin(env: Env, new_admin: Address);
}

/// Minter management trait
pub trait MinterManagementTrait {
    fn add_minter_by_admin(env: Env, minter: Address);
    fn remove_minter_by_admin(env: Env, minter: Address);
    fn get_minters(env: Env) -> Vec<Address>;
    fn is_minter(env: Env, address: Address) -> bool;
}

/// Token operations trait
pub trait TokenOperationsTrait {
    fn mint(env: Env, from: Address, to: Address, amount: i128);
    fn burn(env: Env, from: Address, amount: i128);
}

/// Query trait
pub trait QueryTrait {
    fn token_contract(env: Env) -> Address;
}

#[contractclient(name = "MinterClient")]
/// Minter Manager Interface
pub trait MinterManagerInterface {
    /// Initialize the contract
    ///
    /// # Parameters
    /// - `admin`: Admin address
    /// - `token_contract`: Token contract address
    fn initialize(env: Env, admin: Address, token_contract: Address);

    /// Add minter by admin
    fn add_minter_by_admin(env: Env, minter: Address);

    /// Remove minter by admin
    fn remove_minter_by_admin(env: Env, minter: Address);

    /// Check if an address is a minter
    fn is_minter(env: Env, minter: Address) -> bool;

    /// Get all minters
    fn get_minters(env: Env) -> Vec<Address>;

    /// Mint tokens (only callable by minters)
    fn mint(env: Env, from: Address, to: Address, amount: i128);

    /// Burn tokens (only callable by minters)
    fn burn(env: Env, from: Address, amount: i128);

    /// Get token contract address
    fn get_token_contract(env: Env) -> Address;

    /// Get admin address
    fn admin(env: Env) -> Address;
}
