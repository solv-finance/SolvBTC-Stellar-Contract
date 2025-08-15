use soroban_sdk::{contractclient, Address, Env, Vec};

// 1. Mintable functionality trait 
pub trait MintableToken {
    /// Mint tokens (minter role only)
    fn mint_from(env: Env, from: Address, to: Address, amount: i128);
}

// 2. Blacklist functionality trait 
pub trait BlacklistTrait {
    /// Add address to blacklist (blacklist manager role only)
    fn add_to_blacklist(env: Env, from: Address, address: Address);

    /// Remove address from blacklist (blacklist manager role only)
    fn remove_from_blacklist(env: Env, from: Address, address: Address);

    /// Check if address is in blacklist
    fn is_blacklisted(env: Env, address: Address) -> bool;

    /// Burn all tokens of a blacklisted address (admin role only)
    fn burn_blacklisted_tokens_by_admin(env: Env, address: Address);
}

// 3. Minter management functionality trait
pub trait MinterManagementTrait {
    /// Add minter by admin (admin only)
    fn add_minter_by_admin(env: Env, minter: Address);

    /// Remove minter by admin (admin only)
    fn remove_minter_by_admin(env: Env, minter: Address);

    /// Get all minters
    fn get_minters(env: Env) -> Vec<Address>;

    /// Check if address is minter
    fn is_minter(env: Env, address: Address) -> bool;
}