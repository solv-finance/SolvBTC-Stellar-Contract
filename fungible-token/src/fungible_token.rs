use soroban_sdk::{
    contract, contracterror, contractimpl, contractmeta, contracttype, log, panic_with_error,
    Address, Env, String, Symbol,
};
use stellar_fungible;
use stellar_pausable;

// Import our defined traits
use crate::traits::{
    AdminTrait, BlacklistTrait, BurnableToken, InternalHelperTrait, MintableToken, PausableToken,
    TokenInterface,
};

/********** Ledger Thresholds **********/

const ONE_DAY_LEDGERS: u32 = 17280; // assumes 5s a ledger

const LEDGER_THRESHOLD_INSTANCE: u32 = ONE_DAY_LEDGERS * 30; // ~ 30 days
const LEDGER_BUMP_INSTANCE: u32 = LEDGER_THRESHOLD_INSTANCE + ONE_DAY_LEDGERS; // ~ 31 days

const LEDGER_THRESHOLD_SHARED: u32 = ONE_DAY_LEDGERS * 45; // ~ 45 days
const LEDGER_BUMP_SHARED: u32 = LEDGER_THRESHOLD_SHARED + ONE_DAY_LEDGERS; // ~ 46 days

const LEDGER_THRESHOLD_USER: u32 = ONE_DAY_LEDGERS * 100; // ~ 100 days
const LEDGER_BUMP_USER: u32 = LEDGER_THRESHOLD_USER + 20 * ONE_DAY_LEDGERS; // ~ 120 days

// Token contract data keys
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    // Token metadata
    Metadata,
    // Contract admin
    Admin,
    // Initialization status
    Initialized,
    // Mint authorization
    MintAuthorization,
}

// Blacklist data keys
#[derive(Clone)]
#[contracttype]
pub enum BlacklistDataKey {
    BlackListAddress(Address),
}

// Token metadata structure
#[derive(Clone)]
#[contracttype]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u32,
}

// Contract error types
#[derive(Clone, Debug, Copy, Eq, PartialEq, PartialOrd, Ord)]
#[contracterror]
#[repr(u32)]
pub enum TokenError {
    // Insufficient permissions
    Unauthorized = 1,
    // Contract is paused
    Paused = 2,
    // Insufficient balance
    InsufficientBalance = 3,
    // Invalid argument
    InvalidArgument = 4,
    // Contract already initialized
    AlreadyInitialized = 5,
    // Contract not initialized
    NotInitialized = 6,
    // Invalid address
    InvalidAddress = 7,
    // Amount must be positive
    InvalidAmount = 8,
    // Address is blacklisted
    AddressBlacklisted = 9,
}

// FungibleToken contract
#[contract]
pub struct FungibleToken;

// ==================== Core Token Functionality Implementation ====================

#[contractimpl]
impl TokenInterface for FungibleToken {
    fn initialize(
        env: Env,
        admin: Address,
        name: String,
        symbol: String,
        decimals: u32,
        mint_authorization: Address,
    ) {
        // Verify admin permissions
        admin.require_auth();
        // Check if already initialized
        if Self::is_initialized_internal(&env) {
            panic_with_error!(env, TokenError::AlreadyInitialized);
        }

        // Validate parameters
        if decimals > 18 {
            panic_with_error!(env, TokenError::InvalidArgument);
        }

        // Set contract admin
        env.storage().instance().set(&DataKey::Admin, &admin);
        // Set mint authorization
        env.storage()
            .instance()
            .set(&DataKey::MintAuthorization, &mint_authorization);

        // Set token metadata
        let metadata = TokenMetadata {
            name: name.clone(),
            symbol: symbol.clone(),
            decimals,
        };
        env.storage().instance().set(&DataKey::Metadata, &metadata);

        // Mark as initialized
        env.storage().instance().set(&DataKey::Initialized, &true);

        // Publish initialization event
        env.events().publish(
            (Symbol::new(&env, "initialize"),),
            (admin.clone(), name, symbol, decimals),
        );
    }

    fn name(env: Env) -> String {
        Self::get_metadata(&env).name
    }

    fn symbol(env: Env) -> String {
        Self::get_metadata(&env).symbol
    }

    fn decimals(env: Env) -> u32 {
        Self::get_metadata(&env).decimals
    }

    fn total_supply(env: Env) -> i128 {
        stellar_fungible::total_supply(&env)
    }

    fn balance_of(env: Env, account: Address) -> i128 {
        stellar_fungible::balance(&env, &account)
    }

    fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        // Check if paused
        Self::require_not_paused(&env);

        // Check blacklist
        Self::require_not_blacklisted(&env, &from);
        Self::require_not_blacklisted(&env, &to);

        // Validate parameters
        Self::require_positive_amount(&env, amount);

        // Use OpenZeppelin FungibleToken transfer
        stellar_fungible::transfer(&env, &from, &to, amount);

        // Publish transfer event
        env.events()
            .publish((Symbol::new(&env, "transfer"),), (from, to, amount));
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128) {
        // Check if paused
        Self::require_not_paused(&env);

        // Check blacklist
        Self::require_not_blacklisted(&env, &from);

        // Validate parameters
        Self::require_non_negative_amount(&env, amount);

        // Set authorization validity period
        let live_until_ledger = env.ledger().sequence() + LEDGER_THRESHOLD_USER;

        // Use OpenZeppelin FungibleToken approve
        stellar_fungible::approve(&env, &from, &spender, amount, live_until_ledger);

        // Publish approval event
        env.events().publish(
            (Symbol::new(&env, "approve"),),
            (from, spender, amount, live_until_ledger),
        );
    }

    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        stellar_fungible::allowance(&env, &from, &spender)
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        // Check if paused
        Self::require_not_paused(&env);

        // Check blacklist (including spender)
        Self::require_not_blacklisted(&env, &spender);
        Self::require_not_blacklisted(&env, &from);
        Self::require_not_blacklisted(&env, &to);

        // Validate parameters
        Self::require_positive_amount(&env, amount);

        // Use the passed spender parameter, don't force using contract address
        // Use OpenZeppelin FungibleToken proxy transfer
        stellar_fungible::transfer_from(&env, &spender, &from, &to, amount);

        // Publish proxy transfer event
        env.events().publish(
            (Symbol::new(&env, "transfer_from"),),
            (spender, from, to, amount),
        );
    }

    fn is_initialized(env: Env) -> bool {
        Self::is_initialized_internal(&env)
    }
}

// ==================== Mintable Functionality Implementation ====================

#[contractimpl]
impl MintableToken for FungibleToken {
    fn mint(env: Env, to: Address, amount: i128) {
        // Check if paused
        Self::require_not_paused(&env);

        // Validate parameters
        Self::require_positive_amount(&env, amount);
        // Verify minting authorization
        let minter = Self::require_mint_authorization(&env);

        // Use OpenZeppelin FungibleToken minting
        stellar_fungible::mintable::mint(&env, &to, amount);

        // Publish minting event
        env.events()
            .publish((Symbol::new(&env, "mint"),), (minter, to, amount));
    }
}

// ==================== Burnable Functionality Implementation ====================

#[contractimpl]
impl BurnableToken for FungibleToken {
    fn burn(env: Env, amount: i128) {
        // Check if paused
        Self::require_not_paused(&env);

        // Validate parameters
        Self::require_positive_amount(&env, amount);

        let minter = Self::require_burn_authorization(&env);

        // Use OpenZeppelin FungibleToken burning
        stellar_fungible::burnable::burn(&env, &minter, amount);

        // Publish burning event
        env.events()
            .publish((Symbol::new(&env, "burn"),), (minter, amount));
    }
}

// ==================== Pausable Functionality Implementation ====================

#[contractimpl]
impl PausableToken for FungibleToken {
    fn pause(env: Env) {
        let admin = Self::require_admin_address(&env);

        // Use OpenZeppelin pause function
        stellar_pausable::pause(&env, &admin);

        // Publish pause event
        env.events().publish((Symbol::new(&env, "pause"),), admin);
    }

    fn unpause(env: Env) {
        let admin = Self::require_admin_address(&env);

        // Use OpenZeppelin unpause function
        stellar_pausable::unpause(&env, &admin);

        // Publish unpause event
        env.events().publish((Symbol::new(&env, "unpause"),), admin);
    }

    fn is_paused(env: Env) -> bool {
        stellar_pausable::paused(&env)
    }
}

// ==================== Blacklist Functionality Implementation ====================

#[contractimpl]
impl BlacklistTrait for FungibleToken {
    fn add_to_blacklist(env: Env, address: Address) {
        let admin = Self::require_admin(&env);

        // Add to blacklist
        Self::add_blacklist(&env, &address);

        // Publish blacklist addition event
        env.events()
            .publish((Symbol::new(&env, "blacklist_add"),), (admin, address));
    }

    fn remove_from_blacklist(env: Env, address: Address) {
        let admin = Self::require_admin(&env);

        // Remove from blacklist
        Self::remove_blacklist(&env, &address);

        // Publish blacklist removal event
        env.events()
            .publish((Symbol::new(&env, "blacklist_remove"),), (admin, address));
    }

    fn is_blacklisted(env: Env, address: Address) -> bool {
        Self::is_blacklist(&env, &address)
    }
}

// ==================== Admin Functionality Implementation ====================

#[contractimpl]
impl AdminTrait for FungibleToken {
    fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    fn transfer_admin(env: Env, new_admin: Address) {
        let current_admin = Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Admin, &new_admin);

        // Publish admin transfer event
        env.events().publish(
            (Symbol::new(&env, "admin_transfer"),),
            (current_admin, new_admin),
        );
    }

    fn transfer_mint_authorization(env: Env, new_mint_authorization: Address) {
        let current_admin = Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::MintAuthorization, &new_mint_authorization);

        // Publish mint authorization transfer event
        env.events().publish(
            (Symbol::new(&env, "mint_authorization_transfer"),),
            (current_admin, new_mint_authorization),
        );
    }

    fn mint_authorization(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::MintAuthorization)
    }
}

// ==================== Internal Helper Functions Implementation ====================

impl InternalHelperTrait for FungibleToken {
    fn require_admin(env: &Env) -> Address {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, TokenError::Unauthorized));
        admin.require_auth();
        admin
    }

    fn require_admin_address(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, TokenError::Unauthorized))
    }

    fn require_not_paused(env: &Env) {
        if stellar_pausable::paused(env) {
            panic_with_error!(env, TokenError::Paused);
        }
    }

    fn require_positive_amount(env: &Env, amount: i128) {
        if amount <= 0 {
            panic_with_error!(env, TokenError::InvalidAmount);
        }
    }

    fn require_non_negative_amount(env: &Env, amount: i128) {
        if amount < 0 {
            panic_with_error!(env, TokenError::InvalidAmount);
        }
    }

    fn require_not_blacklisted(env: &Env, address: &Address) {
        if Self::is_blacklist(env, address) {
            panic_with_error!(env, TokenError::AddressBlacklisted);
        }
    }

    fn require_mint_authorization(env: &Env) -> Address {
        let mint_authorization: Address = env
            .storage()
            .instance()
            .get(&DataKey::MintAuthorization)
            .unwrap_or_else(|| panic_with_error!(env, TokenError::Unauthorized));
        mint_authorization.require_auth();
        mint_authorization
    }

    fn require_burn_authorization(env: &Env) -> Address {
        let burn_authorization: Address = env
            .storage()
            .instance()
            .get(&DataKey::MintAuthorization)
            .unwrap_or_else(|| panic_with_error!(env, TokenError::Unauthorized));
        burn_authorization
    }
}

// ==================== Private Helper Functions ====================

impl FungibleToken {
    // Check if contract is initialized
    fn is_initialized_internal(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Initialized)
            .unwrap_or(false)
    }

    // Get token metadata
    fn get_metadata(env: &Env) -> TokenMetadata {
        env.storage()
            .instance()
            .get(&DataKey::Metadata)
            .unwrap_or(TokenMetadata {
                name: String::from_str(env, "Unknown"),
                symbol: String::from_str(env, "UNK"),
                decimals: 18,
            })
    }

    // Add address to blacklist
    fn add_blacklist(env: &Env, address: &Address) {
        env.storage()
            .instance()
            .set(&BlacklistDataKey::BlackListAddress(address.clone()), &true);
    }

    // Remove address from blacklist
    fn remove_blacklist(env: &Env, address: &Address) {
        env.storage()
            .instance()
            .remove(&BlacklistDataKey::BlackListAddress(address.clone()));
    }

    // Check if address is blacklisted
    fn is_blacklist(env: &Env, address: &Address) -> bool {
        env.storage()
            .instance()
            .get(&BlacklistDataKey::BlackListAddress(address.clone()))
            .unwrap_or(false)
    }
}
