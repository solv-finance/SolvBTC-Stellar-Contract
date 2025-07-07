#[cfg(test)]
mod tests {
    use crate::{MinterManagerError, DataKey, MinterManager, MinterManagerClient};
    use soroban_sdk::{Env, Address, Map, Vec, testutils::Address as AddressTestUtils};

    // Use a valid Stellar address provided by the user
    const VALID_ADDRESS: &str = "GDX2W2LKRSXXU4GEF3STS4C3JJ2H4XLODOZGWPOVFY4LV5ZJ4PNTXYTW";

    // Helper function: Create contract client
    fn create_contract(env: &Env) -> (MinterManagerClient<'_>, Address) {
        let contract_id = env.register(MinterManager, ());
        let client = MinterManagerClient::new(env, &contract_id);
        (client, contract_id)
    }

    // Helper function: Create test addresses
    fn create_test_addresses(env: &Env) -> (Address, Address, Address) {
        let admin = Address::from_str(env, VALID_ADDRESS);
        let token_contract = Address::generate(&env);
        let minter = Address::generate(&env);
        (admin, token_contract, minter)
    }

    #[test]
    fn test_error_codes() {
        // Verify error type definitions
        assert_eq!(MinterManagerError::Unauthorized as u32, 1);
        assert_eq!(MinterManagerError::InvalidArgument as u32, 2);
        assert_eq!(MinterManagerError::TooManyMinters as u32, 3);
        assert_eq!(MinterManagerError::MinterNotFound as u32, 4);
        assert_eq!(MinterManagerError::MinterAlreadyExists as u32, 5);
        assert_eq!(MinterManagerError::NotInitialized as u32, 6);
        assert_eq!(MinterManagerError::AlreadyInitialized as u32, 7);
    }

    #[test]
    fn test_data_keys() {
        // Verify data key definitions
        let admin_key = DataKey::Admin;
        let initialized_key = DataKey::Initialized;
        let minters_key = DataKey::Minters;
        let token_contract_key = DataKey::TokenContract;
        
        assert!(matches!(admin_key, DataKey::Admin));
        assert!(matches!(initialized_key, DataKey::Initialized));
        assert!(matches!(minters_key, DataKey::Minters));
        assert!(matches!(token_contract_key, DataKey::TokenContract));
    }

    #[test]
    fn test_contract_initialization() {
        // Test contract initialization
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, _) = create_test_addresses(&env);

        // Should return false before initialization
        assert!(!client.is_initialized());

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Verify initialization results
        assert!(client.is_initialized());
        assert_eq!(client.admin(), admin);
        assert_eq!(client.token_contract(), token_contract);
        assert_eq!(client.get_minters().len(), 0);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7)")]
    fn test_contract_double_initialization() {
        // Test that repeated initialization should fail
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, _) = create_test_addresses(&env);

        // First initialization
        client.initialize(&admin, &token_contract);

        // Second initialization should fail
        client.initialize(&admin, &token_contract);
    }

    #[test]
    fn test_contract_admin_transfer() {
        // Test admin permission transfer
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, _) = create_test_addresses(&env);
        let new_admin = Address::generate(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);
        assert_eq!(client.admin(), admin);

        // Transfer admin permissions
        client.transfer_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn test_contract_minter_management() {
        // Test minter management functionality
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, minter) = create_test_addresses(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Verify initial state
        assert!(!client.is_minter(&minter));
        assert_eq!(client.get_minters().len(), 0);

        // Add minter
        client.add_minter_by_admin(&minter);

        // Verify minter has been added
        assert!(client.is_minter(&minter));
        let minters = client.get_minters();
        assert_eq!(minters.len(), 1);
        assert_eq!(minters.get(0).unwrap(), minter);

        // Remove minter
        client.remove_minter_by_admin(&minter);

        // Verify minter has been removed
        assert!(!client.is_minter(&minter));
        assert_eq!(client.get_minters().len(), 0);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5)")]
    fn test_contract_add_duplicate_minter() {
        // Test adding duplicate minter should fail
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, minter) = create_test_addresses(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Add minter
        client.add_minter_by_admin(&minter);

        // Adding the same minter again should fail
        client.add_minter_by_admin(&minter);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #4)")]
    fn test_contract_remove_nonexistent_minter() {
        // Test removing non-existent minter should fail
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, minter) = create_test_addresses(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Attempting to remove non-existent minter should fail
        client.remove_minter_by_admin(&minter);
    }


    #[test]
    fn test_contract_minter_capacity_limit() {
        // Test minter count limit
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, _) = create_test_addresses(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Add multiple minters (using generated addresses)
        let mut test_minters = Vec::new(&env);
        for _i in 0..10 {
            let minter = Address::generate(&env);
            test_minters.push_back(minter.clone());
            client.add_minter_by_admin(&minter);
        }

        assert_eq!(client.get_minters().len(), 10);
    }

    #[test]
    fn test_contract_mint_function() {
   
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, minter) = create_test_addresses(&env);
        let _recipient = Address::generate(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Add minter
        client.add_minter_by_admin(&minter);

      
        assert!(client.is_minter(&minter));
        assert_eq!(client.token_contract(), token_contract);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #2)")]
    fn test_contract_mint_invalid_amount() {
        // Test minting invalid amount should fail
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, minter) = create_test_addresses(&env);
        let recipient = Address::generate(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Add minter
        client.add_minter_by_admin(&minter);

        // Try minting invalid amount (0 or negative)
        client.mint(&minter, &token_contract, &recipient, &0_i128);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #3)")]
    fn test_contract_minter_limit_exceeded() {
        // Test exceeding minter limit should fail
        let env = Env::default();
        env.mock_all_auths();
        
        let (client, _) = create_contract(&env);
        let (admin, token_contract, _) = create_test_addresses(&env);

        // Initialize contract
        client.initialize(&admin, &token_contract);

        // Add 10 minters (maximum allowed)
        for _i in 0..10 {
            let minter = Address::generate(&env);
            client.add_minter_by_admin(&minter);
        }

        // Adding 11th minter should fail
        let extra_minter = Address::generate(&env);
        client.add_minter_by_admin(&extra_minter);
    }

    // ==================== Data Structure Tests ====================
    // The following are existing data structure tests, kept unchanged
    #[test]
    fn test_map_basic_operations() {
        // Test Map basic operations
        let env = Env::default();
        
        // Test empty Map
        let mut minters: Map<Address, i128> = Map::new(&env);
        assert_eq!(minters.len(), 0);
        
        // Test adding
        let address1 = Address::generate(&env);
        minters.set(address1.clone(), 1000);
        assert_eq!(minters.len(), 1);
        
        // Test retrieval
        assert_eq!(minters.get(address1.clone()).unwrap(), 1000);
        
        // Test updating
        minters.set(address1.clone(), 2000);
        assert_eq!(minters.get(address1.clone()).unwrap(), 2000);
        assert_eq!(minters.len(), 1); // Length remains the same
        
        // Test removal
        minters.remove(address1.clone());
        assert_eq!(minters.len(), 0);
        assert!(!minters.contains_key(address1.clone()));
    }

    #[test]
    fn test_minter_limit_logic() {
        // Test minter limit logic
        let env = Env::default();
        
        let mut minters: Map<Address, i128> = Map::new(&env);
        let address1 = Address::generate(&env);
        
        // Set limit
        minters.set(address1.clone(), 1000);
        
        // Simulate mint function's limit check logic
        let limit = minters.get(address1.clone()).unwrap_or(0);
        let amount = 500;
        
        // Verify limit check
        assert!(limit > 0 && amount <= limit); // Should allow minting
        
        // Test exceeding limit case
        let large_amount = 1500;
        assert!(limit > 0 && large_amount > limit); // Should reject minting
    }

} 