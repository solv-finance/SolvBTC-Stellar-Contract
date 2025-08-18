use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    Address, Env, String, Symbol, Vec, Map,
};
use stellar_fungible::{
    burnable::FungibleBurnable, impl_token_interface, Base, FungibleToken
};
use stellar_pausable::{self as pausable, Pausable};
use stellar_pausable_macros::when_not_paused;
use stellar_ownable::{self as ownable, Ownable};
use stellar_ownable_macro::only_owner;
use stellar_default_impl_macro::default_impl;


// Import our defined traits  
use crate::traits::{
    BlacklistTrait, MintableToken, MinterManagementTrait,
};

// Constants
const MAX_MINTERS: u32 = 10;

// Data keys
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    // Minters mapping (Address -> Minting limit)
    Minters,
    // Blacklisted addresses
    BlackListAddress(Address),
    // Blacklist manager
    BlacklistManager,
    // Minter manager
    MinterManager,
}

// Contract error types
#[derive(Clone, Debug, Copy, Eq, PartialEq, PartialOrd, Ord)]
#[contracterror]
#[repr(u32)]
pub enum TokenError {
    // Insufficient permissions
    Unauthorized = 150,
    // Contract is paused
    Paused = 151,
    // Insufficient balance
    InsufficientBalance = 152,
    // Invalid argument
    InvalidArgument = 153,
    // Contract already initialized
    AlreadyInitialized = 154,
    // Contract not initialized
    NotInitialized = 155,
    // Invalid address
    InvalidAddress = 156,
    // Amount must be positive
    InvalidAmount = 157,
    // Address is blacklisted
    AddressBlacklisted = 158,
    // Maximum number of minters reached
    TooManyMinters = 159,
    // Minter not found
    MinterNotFound = 160,
    // Minter already exists
    MinterAlreadyExists = 161,
}

// FungibleToken contract
#[contract]
pub struct FungibleTokenContract;

// ==================== Constructor ====================

#[contractimpl]
impl FungibleTokenContract {
    pub fn __constructor(
        env: &Env,
        admin: Address,
        minter_manager: Address,
        blacklist_manager: Address,
        name: String,
        symbol: String,
        decimals: u32,
    ) {
        // Set token metadata using Base
        Base::set_metadata(env, decimals, name.clone(), symbol.clone());
        
        // Set contract owner using OpenZeppelin Ownable
        ownable::set_owner(env, &admin);

        // Initialize empty minters mapping
        let minters: Map<Address, i128> = Map::new(env);
        env.storage().instance().set(&DataKey::Minters, &minters);

        // Set the blacklist manager
        env.storage()
            .instance()
            .set(&DataKey::BlacklistManager, &blacklist_manager);

        // Set the minter manager  
        env.storage()
            .instance()
            .set(&DataKey::MinterManager, &minter_manager);

        // Publish initialization event
        env.events().publish(
            (Symbol::new(env, "initialize"),),
            (admin.clone(), name, symbol, decimals),
        );
    }
}

// ==================== Pausable Functionality Implementation ====================

#[contractimpl]
impl Pausable for FungibleTokenContract {
    fn paused(env: &Env) -> bool {
        pausable::paused(env)
    }

    #[only_owner]
    fn pause(env: &Env, from: Address) {
        pausable::pause(env);
        
        // Emit event
        env.events().publish(
            (Symbol::new(env, "pause"),),
            from,
        );
    }

    #[only_owner]
    fn unpause(env: &Env, from: Address) {
        pausable::unpause(env);
        
        // Emit event
        env.events().publish(
            (Symbol::new(env, "unpause"),),
            from,
        );
    }
}

// ==================== Core Token Functionality Implementation ====================

#[default_impl]
#[contractimpl]
impl FungibleToken for FungibleTokenContract {
    type ContractType = Base;

    #[when_not_paused]
    fn transfer(env: &Env, from: Address, to: Address, amount: i128) {
        // Check blacklist
        Self::require_not_blacklisted(env, &from);
        Self::require_not_blacklisted(env, &to);
        Base::transfer(env, &from, &to, amount);
    }

    #[when_not_paused]
    fn transfer_from(env: &Env, spender: Address, from: Address, to: Address, amount: i128) {
        // Check blacklist (including spender)
        Self::require_not_blacklisted(env, &spender);
        Self::require_not_blacklisted(env, &from);
        Self::require_not_blacklisted(env, &to);
        Base::transfer_from(env, &spender, &from, &to, amount);
    }

    fn approve(env: &Env, owner: Address, spender: Address, amount: i128, live_until_ledger: u32) {
        // Check blacklist
        Self::require_not_blacklisted(env, &owner);
        Self::require_not_blacklisted(env, &spender);
        Base::approve(env, &owner, &spender, amount, live_until_ledger);
    }
}

// ==================== Burnable Functionality Implementation (SEP-41) ====================

#[contractimpl]
impl FungibleBurnable for FungibleTokenContract {
    #[when_not_paused]
    fn burn(env: &Env, from: Address, amount: i128) {
        // SEP-41 standard: user can burn their own tokens
        Base::burn(env, &from, amount);
    }

    #[when_not_paused]
    fn burn_from(env: &Env, spender: Address, from: Address, amount: i128) {
        // SEP-41 standard: burn using allowance mechanism
        Base::burn_from(env, &spender, &from, amount);
    }
}

// ==================== Mintable Functionality Implementation ====================

#[contractimpl]
impl MintableToken for FungibleTokenContract {
    #[when_not_paused]
    fn mint_from(env: Env, from: Address, to: Address, amount: i128) {
        // Validate amount
        Self::require_positive_amount(&env, amount);
        
        // Check if caller is a minter
        Self::require_minter(&env, &from);
        
        // Check blacklist
        Self::require_not_blacklisted(&env, &to);

        // Use Base mint functionality
        Base::mint(&env, &to, amount);

    }
}

// ==================== Blacklist Functionality Implementation ====================

#[contractimpl]
impl BlacklistTrait for FungibleTokenContract {
    fn add_to_blacklist(env: Env, from: Address, address: Address) {
        // Check if from is the blacklist manager
        Self::require_blacklist_manager(&env, &from);
        
        // Add to blacklist
        Self::add_blacklist(&env, &address);

        // Publish blacklist addition event
        env.events()
            .publish((Symbol::new(&env, "blacklist_add"),), (from, address));
    }

    fn remove_from_blacklist(env: Env, from: Address, address: Address) {
        // Check if from is the blacklist manager
        Self::require_blacklist_manager(&env, &from);
        
        // Remove from blacklist
        Self::remove_blacklist(&env, &address);

        // Publish blacklist removal event
        env.events().publish((Symbol::new(&env, "blacklist_remove"), address.clone()), from);
    }

    fn is_blacklisted(env: Env, address: Address) -> bool {
        Self::is_blacklist(&env, &address)
    }

    #[only_owner]
    fn burn_blacklisted_tokens_by_admin(env: Env, address: Address) {
        
        // Verify the address is actually blacklisted
        if !Self::is_blacklist(&env, &address) {
            panic_with_error!(&env, TokenError::InvalidArgument);
        }
        
        // Get current balance
        let balance = Base::balance(&env, &address);
        if balance > 0 {
            // Use our custom burn function that bypasses authorization
            Self::admin_burn_tokens(&env, &address, balance);
        }

        // Publish admin burn event
        env.events().publish((Symbol::new(&env, "burn_blacklisted_tokens_by_admin"), address.clone()), ownable::get_owner(&env));
    }


}

// ==================== Minter Management Functionality Implementation ====================

#[contractimpl]
impl MinterManagementTrait for FungibleTokenContract {
    fn add_minter_by_manager(env: Env, minter: Address) {
        // Get minter manager and require authorization
        let manager: Option<Address> = env.storage()
            .instance()
            .get(&DataKey::MinterManager);
        
        let manager_addr = manager.unwrap_or_else(|| panic_with_error!(&env, TokenError::Unauthorized));
        manager_addr.require_auth();
        
        // Get current minters mapping
        let mut minters: Map<Address, i128> =
            env.storage().instance().get(&DataKey::Minters).unwrap();

        // Check minter count limit (max 10)
        if minters.len() >= MAX_MINTERS {
            panic_with_error!(&env, TokenError::TooManyMinters);
        }

        // Check if minter already exists
        if minters.contains_key(minter.clone()) {
            panic_with_error!(&env, TokenError::MinterAlreadyExists);
        }

        // Add new minter with default limit 0 (needs to be set separately)
        minters.set(minter.clone(), 0);
        env.storage().instance().set(&DataKey::Minters, &minters);

        // Publish add minter event
        env.events().publish(
            (Symbol::new(&env, "minter_added"), minter.clone()),
            manager_addr,
        );
    }
    
    fn remove_minter_by_manager(env: Env, minter: Address) {
        // Get minter manager and require authorization
        let manager: Option<Address> = env.storage()
            .instance()
            .get(&DataKey::MinterManager);
        
        let manager_addr = manager.unwrap_or_else(|| panic_with_error!(&env, TokenError::Unauthorized));
        manager_addr.require_auth();
        
        // Get current minters mapping
        let mut minters: Map<Address, i128> =
            env.storage().instance().get(&DataKey::Minters).unwrap();

        // Check if minter exists
        if !minters.contains_key(minter.clone()) {
            panic_with_error!(&env, TokenError::MinterNotFound);
        }

        // Remove minter
        minters.remove(minter.clone());
        env.storage().instance().set(&DataKey::Minters, &minters);

        // Publish remove minter event
        env.events().publish(
            (Symbol::new(&env, "minter_removed"), minter.clone()),
            manager_addr,
        );
    }
    
    fn get_minters(env: Env) -> Vec<Address> {
        let minters: Map<Address, i128> = env.storage().instance().get(&DataKey::Minters).unwrap();
        let mut result: Vec<Address> = Vec::new(&env);

        // Iterate through Map to get all addresses
        for (address, _) in minters.iter() {
            result.push_back(address);
        }

        result
    }
    
    fn is_minter(env: Env, address: Address) -> bool {
        let minters: Map<Address, i128> = env.storage().instance().get(&DataKey::Minters).unwrap();
        minters.contains_key(address)
    }
}

// ==================== Role Management Functions (Admin Only) ====================

#[contractimpl]
impl FungibleTokenContract {
    /// Set blacklist manager to a new address (owner only)
    #[only_owner]
    pub fn set_blacklist_manager(env: Env, new_manager: Address) {
        env.storage()
            .instance()
            .set(&DataKey::BlacklistManager, &new_manager);
        
        env.events().publish(
            (Symbol::new(&env, "blacklist_manager_changed"), new_manager.clone()),
            ownable::get_owner(&env),
        );
    }

    /// Set minter manager to a new address (owner only)
    #[only_owner]
    pub fn set_minter_manager(env: Env, new_manager: Address) {
        env.storage()
            .instance()
            .set(&DataKey::MinterManager, &new_manager);
        
        env.events().publish(
            (Symbol::new(&env, "minter_manager_changed"), new_manager.clone()),
            ownable::get_owner(&env),
        );
    }


    /// Check if an address is the blacklist manager
    pub fn is_blacklist_manager(env: Env, address: Address) -> bool {
        let manager: Option<Address> = env.storage()
            .instance()
            .get(&DataKey::BlacklistManager);
        manager == Some(address)
    }

    /// Get the current blacklist manager address
    pub fn get_blacklist_manager(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::BlacklistManager)
    }

    /// Check if an address is the minter manager
    pub fn is_minter_manager(env: Env, address: Address) -> bool {
        let manager: Option<Address> = env.storage()
            .instance()
            .get(&DataKey::MinterManager);
        manager == Some(address)
    }

    /// Get the current minter manager address
    pub fn get_minter_manager(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::MinterManager)
    }


}

// ==================== Ownable Implementation ====================

#[default_impl]
#[contractimpl]
impl Ownable for FungibleTokenContract {}

// ==================== Private Helper Functions ====================

impl FungibleTokenContract {
    // Require amount to be positive
    fn require_positive_amount(env: &Env, amount: i128) {
        if amount <= 0 {
            panic_with_error!(env, TokenError::InvalidAmount);
        }
    }

    // Require address not in blacklist
    fn require_not_blacklisted(env: &Env, address: &Address) {
        if Self::is_blacklist(env, address) {
            panic_with_error!(env, TokenError::AddressBlacklisted);
        }
    }

    // Require from to be the blacklist manager
    fn require_blacklist_manager(env: &Env, from: &Address) {
        from.require_auth();
        let manager: Option<Address> = env.storage()
            .instance()
            .get(&DataKey::BlacklistManager);
        if manager != Some(from.clone()) {
            panic_with_error!(env, TokenError::Unauthorized);
        }
    }


    // Validate minter permissions
    fn require_minter(env: &Env, address: &Address) {
        address.require_auth();
        let minters: Map<Address, i128> = env.storage().instance().get(&DataKey::Minters).unwrap();
        if !minters.contains_key(address.clone()) {
            panic_with_error!(env, TokenError::Unauthorized);
        }
    }

    // Add address to blacklist
    fn add_blacklist(env: &Env, address: &Address) {
        env.storage()
            .instance()
            .set(&DataKey::BlackListAddress(address.clone()), &true);
    }

    // Remove address from blacklist
    fn remove_blacklist(env: &Env, address: &Address) {
        env.storage()
            .instance()
            .remove(&DataKey::BlackListAddress(address.clone()));
    }

    // Check if address is blacklisted
    fn is_blacklist(env: &Env, address: &Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::BlackListAddress(address.clone()))
            .unwrap_or(false)
    }

    // Admin burn function that bypasses authorization checks
    // Uses OpenZeppelin's Base::update() directly to avoid require_auth()
    fn admin_burn_tokens(env: &Env, from: &Address, amount: i128) {
        // Use OpenZeppelin's update function directly, bypassing authorization
        // Base::update(e, Some(from), None, amount) handles burning when 'to' is None
        Base::update(env, Some(from), None, amount);

        // Publish burn event using OpenZeppelin's standard event format
        env.events().publish(
            (Symbol::new(env, "burn_blacklisted_tokens_by_admin"), from.clone()),
            amount,
        );
    }
}
// Generate the TokenInterface implementation using OpenZeppelin macro
impl_token_interface!(FungibleTokenContract);

