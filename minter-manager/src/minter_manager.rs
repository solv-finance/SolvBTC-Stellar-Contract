use crate::traits::{
    AdminTrait, InitializableTrait, MinterManagementTrait, QueryTrait, TokenOperationsTrait,
};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, Env, IntoVal,
    Map, Symbol, Vec,
};
const MAX_MINTERS: u32 = 10;
// ==================== Error Definitions ====================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MinterManagerError {
    // Insufficient permissions
    Unauthorized = 1,
    // Invalid argument
    InvalidArgument = 2,
    // Maximum number of minters reached
    TooManyMinters = 3,
    // Minter not found
    MinterNotFound = 4,
    // Minter already exists
    MinterAlreadyExists = 5,
    // Contract not initialized
    NotInitialized = 6,
    // Contract already initialized
    AlreadyInitialized = 7,
}

// ==================== Storage Key Definitions ====================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    // Contract admin
    Admin,
    // Initialization status
    Initialized,
    // Minters mapping (Address -> Minting limit)
    Minters,
    // Token contract address
    TokenContract,
}

// ==================== Contract Implementation ====================

#[contract]
pub struct MinterManager;

// ==================== Initialization Function Implementation ====================

#[contractimpl]
impl InitializableTrait for MinterManager {
    fn initialize(env: Env, admin: Address, token_contract: Address) {
        // Verify admin permissions
        admin.require_auth();
        // Check if already initialized
        if Self::is_initialized_internal(&env) {
            panic_with_error!(&env, MinterManagerError::AlreadyInitialized);
        }

        // Set admin
        env.storage().instance().set(&DataKey::Admin, &admin);

        // Set token contract address
        env.storage()
            .instance()
            .set(&DataKey::TokenContract, &token_contract);

        // Initialize minters mapping
        let minters: Map<Address, i128> = Map::new(&env);
        env.storage().instance().set(&DataKey::Minters, &minters);

        // Mark as initialized
        env.storage().instance().set(&DataKey::Initialized, &true);

        // Publish initialization event
        env.events()
            .publish((Symbol::new(&env, "initialize"),), (admin, token_contract));
    }

    fn is_initialized(env: Env) -> bool {
        Self::is_initialized_internal(&env)
    }
}

// ==================== Admin Function Implementation ====================

#[contractimpl]
impl AdminTrait for MinterManager {
    fn admin(env: Env) -> Address {
        Self::get_admin(&env)
    }

    fn transfer_admin(env: Env, new_admin: Address) {
        let current_admin = Self::require_admin(&env);

        // Set new admin
        env.storage().instance().set(&DataKey::Admin, &new_admin);

        // Publish admin transfer event
        env.events().publish(
            (Symbol::new(&env, "admin_transferred"),),
            (current_admin, new_admin),
        );
    }
}

// ==================== Minter Management Function Implementation ====================

#[contractimpl]
impl MinterManagementTrait for MinterManager {
    fn add_minter_by_admin(env: Env, minter: Address) {
        let admin = Self::require_admin(&env);

        // Get current minters mapping
        let mut minters: Map<Address, i128> =
            env.storage().instance().get(&DataKey::Minters).unwrap();

        // Check minter count limit (max 10)
        if minters.len() >= MAX_MINTERS {
            panic_with_error!(&env, MinterManagerError::TooManyMinters);
        }

        // Check if minter already exists
        if minters.contains_key(minter.clone()) {
            panic_with_error!(&env, MinterManagerError::MinterAlreadyExists);
        }

        // Add new minter, default limit is 0 (needs to be set separately)
        minters.set(minter.clone(), 0);
        env.storage().instance().set(&DataKey::Minters, &minters);

        // Publish add minter event
        env.events().publish(
            (Symbol::new(&env, "minter_added"),),
            (admin, minter, 0_i128),
        );
    }

    fn remove_minter_by_admin(env: Env, minter: Address) {
        let admin = Self::require_admin(&env);

        // Get current minters mapping
        let mut minters: Map<Address, i128> =
            env.storage().instance().get(&DataKey::Minters).unwrap();

        // Check if minter exists
        if !minters.contains_key(minter.clone()) {
            panic_with_error!(&env, MinterManagerError::MinterNotFound);
        }

        // Remove minter
        minters.remove(minter.clone());
        env.storage().instance().set(&DataKey::Minters, &minters);

        // Publish remove minter event
        env.events()
            .publish((Symbol::new(&env, "minter_removed"),), (admin, minter));
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

// ==================== Token Operations Function Implementation ====================

#[contractimpl]
impl TokenOperationsTrait for MinterManager {
    fn mint(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        // Validate parameters
        if amount <= 0 {
            panic_with_error!(&env, MinterManagerError::InvalidArgument);
        }

        // Validate if caller is a minter
        Self::require_minter(&env, &from);

        // Get token contract address
        let token_contract = Self::get_token_contract(&env);

        // Call token contract's mint function
        let token_client = FungibleTokenClient::new(&env, &token_contract);
        token_client.mint(&env, &to, &amount);

        // Publish mint event
        env.events()
            .publish((Symbol::new(&env, "mint"),), (from, to, amount));
    }

    fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        // Validate parameters
        if amount <= 0 {
            panic_with_error!(&env, MinterManagerError::InvalidArgument);
        }

        // Validate if caller is a minter
        Self::require_minter(&env, &from);

        // Get token contract address
        let token_contract = Self::get_token_contract(&env);

        // Call token contract's burn function
        let token_client = FungibleTokenClient::new(&env, &token_contract);
        token_client.burn(&env, &amount);

        // Publish burn event
        env.events()
            .publish((Symbol::new(&env, "burn"),), (from, amount));
    }
}

// ==================== Query Function Implementation ====================

#[contractimpl]
impl QueryTrait for MinterManager {
    fn token_contract(env: Env) -> Address {
        Self::get_token_contract(&env)
    }
}

// ==================== Internal Helper Functions ====================

impl MinterManager {
    /// Get admin address
    fn get_admin(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Get token contract address
    fn get_token_contract(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::TokenContract)
            .unwrap()
    }

    /// Check if contract is initialized
    fn is_initialized_internal(env: &Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    /// Validate admin permissions
    fn require_admin(env: &Env) -> Address {
        let admin = Self::get_admin(env);
        admin.require_auth();
        admin
    }

    /// Validate minter permissions
    fn require_minter(env: &Env, address: &Address) {
        let minters: Map<Address, i128> = env.storage().instance().get(&DataKey::Minters).unwrap();
        if !minters.contains_key(address.clone()) {
            panic_with_error!(env, MinterManagerError::Unauthorized);
        }
    }
}

// ==================== Token Contract Client ====================

#[contracttype]
pub struct FungibleTokenClient {
    contract_id: Address,
}

impl FungibleTokenClient {
    pub fn new(_env: &Env, contract_id: &Address) -> Self {
        Self {
            contract_id: contract_id.clone(),
        }
    }

    pub fn mint(&self, env: &Env, to: &Address, amount: &i128) {
        let args = (to.clone(), amount.clone()).into_val(env);
        let _: () = env.invoke_contract(&self.contract_id, &Symbol::new(env, "mint"), args);
    }

    pub fn burn(&self, env: &Env, amount: &i128) {
        let args = (amount.clone(),).into_val(env);
        let _: () = env.invoke_contract(&self.contract_id, &Symbol::new(env, "burn"), args);
    }
}
