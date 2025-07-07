use soroban_sdk::{Address, Env, String};

// 1. Core token functionality trait
pub trait TokenInterface {
    /// Initialize contract
    fn initialize(env: Env, admin: Address, name: String, symbol: String, decimals: u32, minter: Address);

    /// Get token name
    fn name(env: Env) -> String;
    
    /// Get token symbol
    fn symbol(env: Env) -> String;
    
    /// Get decimal places
    fn decimals(env: Env) -> u32;
    
    /// Get total supply
    fn total_supply(env: Env) -> i128;
    
    /// Get account balance
    fn balance_of(env: Env, account: Address) -> i128;
    
    /// Transfer
    fn transfer(env: Env, from: Address, to: Address, amount: i128);
    
    /// Approve
    fn approve(env: Env, from: Address, spender: Address, amount: i128);
    
    /// Get allowance
    fn allowance(env: Env, owner: Address, spender: Address) -> i128;
    
    /// Transfer from
    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128);
    
    /// Check if initialized
    fn is_initialized(env: Env) -> bool;
}

// 2. Mintable functionality trait
pub trait MintableToken {
    /// Mint tokens (admin only)
    fn mint(env: Env, to: Address, amount: i128);
}

// 3. Burnable functionality trait
pub trait BurnableToken {
    /// Burn tokens
    fn burn(env: Env, amount: i128);
}

// 4. Pausable functionality trait
pub trait PausableToken {
    /// Pause contract (admin only)
    fn pause(env: Env);
    
    /// Unpause contract (admin only)
    fn unpause(env: Env);
    
    /// Check if contract is paused
    fn is_paused(env: Env) -> bool;
}

// 5. Blacklist functionality trait
pub trait BlacklistTrait {
    /// Add address to blacklist (admin only)
    fn add_to_blacklist(env: Env, address: Address);
    
    /// Remove address from blacklist (admin only)
    fn remove_from_blacklist(env: Env, address: Address);
    
    /// Check if address is in blacklist
    fn is_blacklisted(env: Env, address: Address) -> bool;
}

// 6. Admin functionality trait
pub trait AdminTrait {
    /// Get contract admin
    fn admin(env: Env) -> Option<Address>;
    
    /// Transfer admin permission (admin only)
    fn transfer_admin(env: Env, new_admin: Address);

    /// Transfer mint authorization (admin only)
    fn transfer_mint_authorization(env: Env, new_mint_authorization: Address);

    /// Get mint authorization
    fn mint_authorization(env: Env) -> Option<Address>;
}

// 7. Internal helper trait (not exposed externally)
pub(crate) trait InternalHelperTrait {
    /// Require caller to be admin
    fn require_admin(env: &Env) -> Address;
    
    /// Get admin address (no authorization check)
    fn require_admin_address(env: &Env) -> Address;
    
    /// Require contract not paused
    fn require_not_paused(env: &Env);
    
    /// Require amount to be positive
    fn require_positive_amount(env: &Env, amount: i128);
    
    /// Require amount to be non-negative
    fn require_non_negative_amount(env: &Env, amount: i128);
    
    /// Require address not in blacklist
    fn require_not_blacklisted(env: &Env, address: &Address);

    /// Require caller to be mint authorization
    fn require_mint_authorization(env: &Env) -> Address;

    /// Require caller to be burn authorization
    fn require_burn_authorization(env: &Env) -> Address;
} 