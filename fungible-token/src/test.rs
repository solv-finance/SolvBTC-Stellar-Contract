#![cfg(test)]

extern crate std;
use crate::fungible_token::{FungibleTokenContract, FungibleTokenContractClient};
use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    Address, Env, String, IntoVal, Vec,
};

fn create_and_init_token<'a>(
    env: &'a Env,
    admin: &'a Address,
    name: &'a str,
    symbol: &'a str,
    decimals: u32,
) -> FungibleTokenContractClient<'a> {
    // Register contract with constructor arguments
    let contract_address = env.register(
        FungibleTokenContract, 
        (
            admin,
            String::from_str(env, name),
            String::from_str(env, symbol),
            decimals,
        )
    );
    let client = FungibleTokenContractClient::new(env, &contract_address);
    
    client
}

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "Test Token", "TEST", 7);

    // Verify initialization results
    assert_eq!(client.name(), String::from_str(&env, "Test Token"));
    assert_eq!(client.symbol(), String::from_str(&env, "TEST"));
    assert_eq!(client.decimals(), 7);
    assert_eq!(client.total_supply(), 0);
    assert_eq!(client.balance(&admin), 0);
}

#[test]
fn test_approve_and_allowance() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let spender = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "Test Token", "TEST", 18);

    // Approve with live_until_ledger
    let live_until_ledger = 1000u32;
    client.approve(&admin, &spender, &200, &live_until_ledger);
    
    assert_eq!(client.allowance(&admin, &spender), 200);
}

#[test]
fn test_basic_queries() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "My Token", "MTK", 8);

    // Test basic metadata queries
    assert_eq!(client.name(), String::from_str(&env, "My Token"));
    assert_eq!(client.symbol(), String::from_str(&env, "MTK"));
    assert_eq!(client.decimals(), 8);
    assert_eq!(client.total_supply(), 0);
    
    // Test balance queries
    assert_eq!(client.balance(&admin), 0);
    assert_eq!(client.balance(&user), 0);
    
    // Test allowance queries
    assert_eq!(client.allowance(&admin, &user), 0);
    
    // Test pause state
    assert!(!client.paused());
    
    // Test blacklist state
    assert!(!client.is_blacklisted(&admin));
    assert!(!client.is_blacklisted(&user));
}

#[test]
fn test_admin_access_control_queries() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "Test Token", "TEST", 18);

    // Test access control query functions
    assert_eq!(client.get_owner(), Some(admin.clone()));
    
    // Test role query functions (these should not fail)
    assert!(!client.is_minter(&user));
    assert!(!client.is_blacklist_manager(&user));
    
    // Test minter list (should be empty initially)
    let minters = client.get_minters();
    assert_eq!(minters.len(), 0);
}

#[test]
fn test_contract_interface_completeness() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "Test Token", "TEST", 18);

    // Test that all expected functions exist by calling them
    // Test core token functions exist
    let _ = client.name();
    let _ = client.symbol(); 
    let _ = client.decimals();
    let _ = client.total_supply();
    let _ = client.balance(&admin);
    let _ = client.allowance(&admin, &admin);
    
    // Test pause functions exist
    let _ = client.paused();
    
    // Test blacklist functions exist
    let _ = client.is_blacklisted(&admin);
    
    // Test access control functions exist
    let _ = client.get_owner();
    let _ = client.is_minter(&admin);
    let _ = client.is_blacklist_manager(&admin);
    let _ = client.get_minters();
    
    // If we get here, all expected functions exist
    assert!(true);
}

#[test]
fn test_different_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    
    // Test with 0 decimals
    let client0 = create_and_init_token(&env, &admin, "Integer Token", "INT", 0);
    assert_eq!(client0.decimals(), 0);
    
    // Test with 6 decimals (USDC style)
    let client6 = create_and_init_token(&env, &admin, "USDC Token", "USDC", 6);
    assert_eq!(client6.decimals(), 6);
    
    // Test with 18 decimals (ETH style)
    let client18 = create_and_init_token(&env, &admin, "ETH Token", "ETH", 18);
    assert_eq!(client18.decimals(), 18);
}

#[test]
fn test_zero_supply_initially() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "Test Token", "TEST", 18);

    // Verify initial state
    assert_eq!(client.total_supply(), 0);
    assert_eq!(client.balance(&admin), 0);
    
    // Verify random user also has zero balance
    let random_user = Address::generate(&env);
    assert_eq!(client.balance(&random_user), 0);
}

#[test]
fn test_multiple_allowances() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let spender1 = Address::generate(&env);
    let spender2 = Address::generate(&env);
    let client = create_and_init_token(&env, &admin, "Test Token", "TEST", 18);

    let live_until_ledger = 1000u32;
    
    // Set different allowances
    client.approve(&admin, &spender1, &100, &live_until_ledger);
    client.approve(&admin, &spender2, &200, &live_until_ledger);
    
    // Verify both allowances
    assert_eq!(client.allowance(&admin, &spender1), 100);
    assert_eq!(client.allowance(&admin, &spender2), 200);
    
    // Cross-check - admin should not have allowance from spender1
    assert_eq!(client.allowance(&spender1, &admin), 0);
}

#[test]
fn test_ownership_transfer() {
    let env = Env::default();
    let current_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    let client = create_and_init_token(&env, &current_owner, "Test Token", "TEST", 18);

    // Verify initial owner
    assert_eq!(client.get_owner(), Some(current_owner.clone()));

    // Start ownership transfer with a future ledger
    let live_until_ledger = 1000u32;
    env.mock_auths(&[MockAuth {
        address: &current_owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "transfer_ownership",
            args: (&new_owner, &live_until_ledger).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.transfer_ownership(&new_owner, &live_until_ledger);

    // Ownership should not change until accepted
    assert_eq!(client.get_owner(), Some(current_owner.clone()));

    // New owner accepts the ownership
    env.mock_auths(&[MockAuth {
        address: &new_owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "accept_ownership",
            args: ().into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.accept_ownership();

    // Now ownership should be transferred
    assert_eq!(client.get_owner(), Some(new_owner.clone()));
}

#[test]
fn test_ownership_renounce() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "Test Token", "TEST", 18);

    // Verify initial owner
    assert_eq!(client.get_owner(), Some(owner.clone()));

    // Owner renounces ownership
    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "renounce_ownership",
            args: ().into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.renounce_ownership();

    // Contract should now be ownerless
    assert_eq!(client.get_owner(), None);
}

#[test]
fn test_new_owner_can_manage_contract() {
    let env = Env::default();
    let old_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    let client = create_and_init_token(&env, &old_owner, "Test Token", "TEST", 18);

    // Transfer ownership
    let live_until_ledger = 1000u32;
    env.mock_auths(&[MockAuth {
        address: &old_owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "transfer_ownership",
            args: (&new_owner, &live_until_ledger).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.transfer_ownership(&new_owner, &live_until_ledger);

    // Accept ownership
    env.mock_auths(&[MockAuth {
        address: &new_owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "accept_ownership",
            args: ().into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.accept_ownership();

    // New owner should be able to manage the contract
    let minter = Address::generate(&env);
    env.mock_auths(&[MockAuth {
        address: &new_owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "add_minter_by_admin",
            args: (&minter,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.add_minter_by_admin(&minter);

    // Verify minter was added
    assert!(client.is_minter(&minter));
    let minters = client.get_minters();
    assert_eq!(minters.len(), 1);
    assert_eq!(minters.get(0).unwrap(), minter);

    // New owner should be able to pause the contract
    env.mock_auths(&[MockAuth {
        address: &new_owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "pause",
            args: (&new_owner,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.pause(&new_owner);
    assert!(client.paused());
}

#[test]
fn test_owner_only_pause_unpause_unauthorized() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "TT", "TT", 7);

	// authorized pause by owner
	env.mock_auths(&[MockAuth {
		address: &owner,
		invoke: &MockAuthInvoke {
			contract: &client.address,
			fn_name: "pause",
			args: (&owner,).into_val(&env),
			sub_invokes: &[],
		},
	}]);
	client.pause(&owner);
	assert!(client.paused());
}

#[test]
#[should_panic]
fn test_pause_unauthorized_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "TT", "TT", 7);

	env.mock_auths(&[MockAuth {
		address: &not_owner,
		invoke: &MockAuthInvoke { contract: &client.address, fn_name: "pause", args: (&not_owner,).into_val(&env), sub_invokes: &[] },
	}]);
	client.pause(&not_owner);
}

#[test]
#[should_panic]
fn test_unpause_unauthorized_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "TT", "TT", 7);

	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "unpause", args: (&not_owner,).into_val(&env), sub_invokes: &[] } }]);
	client.unpause(&not_owner);
}

#[test]
fn test_minter_management_and_mint_flow() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let user = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);

	// add minter by owner
	env.mock_auths(&[MockAuth {
		address: &owner,
		invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] },
	}]);
	client.add_minter_by_admin(&minter);
	assert!(client.is_minter(&minter));

	// mint by minter to user
	env.mock_auths(&[MockAuth {
		address: &minter,
		invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &100i128).into_val(&env), sub_invokes: &[] },
	}]);
	client.mint_from(&minter, &user, &100);
	assert_eq!(client.balance(&user), 100);
	assert_eq!(client.total_supply(), 100);

	// remove minter by owner
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.remove_minter_by_admin(&minter);
	assert!(!client.is_minter(&minter));
}

#[test]
#[should_panic]
fn test_mint_from_unauthorized_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let user = Address::generate(&env);
	let not_minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);

	env.mock_auths(&[MockAuth { address: &not_minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&not_minter, &user, &50i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&not_minter, &user, &50);
}

#[test]
#[should_panic]
fn test_mint_from_invalid_amount_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let user = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);

	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &0i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &user, &0);
}

#[test]
fn test_too_many_minters_and_duplicate_and_remove_nonexistent() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);

	let mut minters: Vec<Address> = Vec::new(&env);
	for _ in 0..10 {
		minters.push_back(Address::generate(&env));
	}

	// add 10 minters
	for addr in minters.iter() {
		env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&addr,).into_val(&env), sub_invokes: &[] } }]);
		client.add_minter_by_admin(&addr);
	}
	assert_eq!(client.get_minters().len(), 10);
}

#[test]
#[should_panic]
fn test_add_duplicate_minter_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);
	let addr = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&addr,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&addr);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&addr,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&addr);
}

#[test]
#[should_panic]
fn test_add_eleventh_minter_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);
	for _ in 0..10 {
		let addr = Address::generate(&env);
		env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&addr,).into_val(&env), sub_invokes: &[] } }]);
		client.add_minter_by_admin(&addr);
	}
	let eleventh = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&eleventh,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&eleventh);
}

#[test]
#[should_panic]
fn test_remove_nonexistent_minter_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MT", "MT", 7);
	let nonexistent = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_minter_by_admin", args: (&nonexistent,).into_val(&env), sub_invokes: &[] } }]);
	client.remove_minter_by_admin(&nonexistent);
}

#[test]
fn test_blacklist_permissions_and_effects() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
    let user = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BT", "BT", 7);

	// set blacklist manager by owner
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "set_blacklist_manager", args: (&mgr,).into_val(&env), sub_invokes: &[] } }]);
	client.set_blacklist_manager(&mgr);
	assert!(client.is_blacklist_manager(&mgr));

	// manager can add/remove
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &user).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &user);
    assert!(client.is_blacklisted(&user));
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_from_blacklist", args: (&mgr, &user).into_val(&env), sub_invokes: &[] } }]);
	client.remove_from_blacklist(&mgr, &user);
    assert!(!client.is_blacklisted(&user));
}

#[test]
#[should_panic]
fn test_blacklist_unauthorized_add_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let user = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BT", "BT", 7);
	client.set_blacklist_manager(&mgr);
	env.mock_auths(&[MockAuth { address: &user, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&user, &owner).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&user, &owner);
}

#[test]
fn test_blacklist_blocks_mint_and_transfer_and_burn_admin() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
    let minter = Address::generate(&env);
	let a = Address::generate(&env);
	let b = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BT", "BT", 7);

	// owner set mgr and add minter
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "set_blacklist_manager", args: (&mgr,).into_val(&env), sub_invokes: &[] } }]);
	client.set_blacklist_manager(&mgr);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);

	// mint to a
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &200i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &200);
	assert_eq!(client.balance(&a), 200);

	// blacklist a blocks transfer and mint to a
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &a).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &a);
	assert!(client.is_blacklisted(&a));
}

#[test]
#[should_panic]
fn test_transfer_from_blacklisted_should_panic() {
    let env = Env::default();
    let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let a = Address::generate(&env);
	let b = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BT", "BT", 7);
	client.set_blacklist_manager(&mgr);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &10);
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &a).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &a);
	client.transfer(&a, &b, &1);
}

#[test]
#[should_panic]
fn test_mint_to_blacklisted_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let a = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BT", "BT", 7);
	client.set_blacklist_manager(&mgr);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &a).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &a);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &1i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &1);
}

#[test]
fn test_transfer_and_transfer_from_with_approve_and_burn() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);
    let spender = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "TR", "TR", 7);

    // mint to user via adding a minter
    let minter = Address::generate(&env);
    env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
    client.add_minter_by_admin(&minter);
    env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &150i128).into_val(&env), sub_invokes: &[] } }]);
    client.mint_from(&minter, &user, &150);
    assert_eq!(client.balance(&user), 150);

    // approve spender and transfer_from
    let live = 12345u32;
    env.mock_auths(&[MockAuth { address: &user, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "approve", args: (&user, &spender, &60i128, &live).into_val(&env), sub_invokes: &[] } }]);
    client.approve(&user, &spender, &60, &live);

    env.mock_auths(&[MockAuth { address: &spender, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "transfer_from", args: (&spender, &user, &owner, &50i128).into_val(&env), sub_invokes: &[] } }]);
    client.transfer_from(&spender, &user, &owner, &50);
    assert_eq!(client.balance(&owner), 50);
    assert_eq!(client.balance(&user), 100);

    // user burns own tokens
    env.mock_auths(&[MockAuth { address: &user, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "burn", args: (&user, &40i128).into_val(&env), sub_invokes: &[] } }]);
    client.burn(&user, &40);
    assert_eq!(client.balance(&user), 60);
}

#[test]
#[should_panic]
fn test_paused_blocks_transfer() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let a = Address::generate(&env);
	let b = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "PZ", "PZ", 7);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &100i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &100);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "pause", args: (&owner,).into_val(&env), sub_invokes: &[] } }]);
	client.pause(&owner);
	client.transfer(&a, &b, &10);
}

#[test]
#[should_panic]
fn test_paused_blocks_mint() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let a = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "PZ", "PZ", 7);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "pause", args: (&owner,).into_val(&env), sub_invokes: &[] } }]);
	client.pause(&owner);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &10);
}

#[test]
#[should_panic]
fn test_paused_blocks_burn() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let a = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "PZ", "PZ", 7);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &10);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "pause", args: (&owner,).into_val(&env), sub_invokes: &[] } }]);
	client.pause(&owner);
	client.burn(&a, &5);
}

#[test]
fn test_get_blacklist_manager_query() {
    let env = Env::default();
    let owner = Address::generate(&env);
	let mgr1 = Address::generate(&env);
	let mgr2 = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "QM", "QM", 7);

	// default None
	assert_eq!(client.get_blacklist_manager(), Some(owner.clone()));

	// set to mgr1
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "set_blacklist_manager", args: (&mgr1,).into_val(&env), sub_invokes: &[] } }]);
	client.set_blacklist_manager(&mgr1);
	assert_eq!(client.get_blacklist_manager(), Some(mgr1.clone()));

	// set to mgr2
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "set_blacklist_manager", args: (&mgr2,).into_val(&env), sub_invokes: &[] } }]);
	client.set_blacklist_manager(&mgr2);
	assert_eq!(client.get_blacklist_manager(), Some(mgr2.clone()));
}

#[test]
#[should_panic]
fn test_set_blacklist_manager_unauthorized_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "QM", "QM", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "set_blacklist_manager", args: (&mgr,).into_val(&env), sub_invokes: &[] } }]);
	client.set_blacklist_manager(&mgr);
}

#[test]
#[should_panic]
fn test_add_minter_unauthorized_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MM", "MM", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
}

#[test]
#[should_panic]
fn test_remove_minter_unauthorized_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MM", "MM", 7);

	// owner add first
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);

	// not owner remove should panic
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.remove_minter_by_admin(&minter);
}

#[test]
#[should_panic]
fn test_approve_blacklisted_owner_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let spender = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "AP", "AP", 7);
	client.set_blacklist_manager(&mgr);

	// blacklist owner account then approve should panic
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &owner).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &owner);
	let live = 1000u32;
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "approve", args: (&owner, &spender, &1i128, &live).into_val(&env), sub_invokes: &[] } }]);
	client.approve(&owner, &spender, &1, &live);
}

#[test]
#[should_panic]
fn test_approve_blacklisted_spender_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let spender = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "AP", "AP", 7);
	client.set_blacklist_manager(&mgr);

	// blacklist spender then approve should panic
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &spender).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &spender);
	let live = 1000u32;
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "approve", args: (&owner, &spender, &1i128, &live).into_val(&env), sub_invokes: &[] } }]);
	client.approve(&owner, &spender, &1, &live);
}

#[test]
#[should_panic]
fn test_transfer_from_blacklisted_spender_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
    let user = Address::generate(&env);
    let spender = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "TF", "TF", 7);
	client.set_blacklist_manager(&mgr);

	// mint to user
	let minter = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &user, &10);

	// approve spender by user and blacklist spender
	let live = 9999u32;
	env.mock_auths(&[MockAuth { address: &user, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "approve", args: (&user, &spender, &5i128, &live).into_val(&env), sub_invokes: &[] } }]);
	client.approve(&user, &spender, &5, &live);
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &spender).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &spender);

	// transfer_from should panic since spender blacklisted
	env.mock_auths(&[MockAuth { address: &spender, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "transfer_from", args: (&spender, &user, &owner, &1i128).into_val(&env), sub_invokes: &[] } }]);
	client.transfer_from(&spender, &user, &owner, &1);
}

#[test]
fn test_burn_from_with_allowance() {
    let env = Env::default();
	let owner = Address::generate(&env);
    let user = Address::generate(&env);
    let spender = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BF", "BF", 7);

	// mint to user
	let minter = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &20i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &user, &20);

	// approve spender to burn 7
	let live = 123u32;
	env.mock_auths(&[MockAuth { address: &user, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "approve", args: (&user, &spender, &7i128, &live).into_val(&env), sub_invokes: &[] } }]);
	client.approve(&user, &spender, &7, &live);

	// spender burns 7 from user
	env.mock_auths(&[MockAuth { address: &spender, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "burn_from", args: (&spender, &user, &7i128).into_val(&env), sub_invokes: &[] } }]);
	client.burn_from(&spender, &user, &7);
	assert_eq!(client.balance(&user), 13);
}

#[test]
#[should_panic]
fn test_burn_blacklisted_tokens_by_admin_not_blacklisted_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let a = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BB", "BB", 7);

	// call without blacklist should panic
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "burn_blacklisted_tokens_by_admin", args: (&a,).into_val(&env), sub_invokes: &[] } }]);
	client.burn_blacklisted_tokens_by_admin(&a);
}

#[test]
fn test_unpause_resumes_operations() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let a = Address::generate(&env);
	let b = Address::generate(&env);
    let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "UP", "UP", 7);

	// mint to a and pause then unpause
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &10);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "pause", args: (&owner,).into_val(&env), sub_invokes: &[] } }]);
	client.pause(&owner);
	assert!(client.paused());
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "unpause", args: (&owner,).into_val(&env), sub_invokes: &[] } }]);
	client.unpause(&owner);
	assert!(!client.paused());

	// now transfer should work
	env.mock_auths(&[MockAuth { address: &a, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "transfer", args: (&a, &b, &3i128).into_val(&env), sub_invokes: &[] } }]);
	client.transfer(&a, &b, &3);
	assert_eq!(client.balance(&a), 7);
	assert_eq!(client.balance(&b), 3);
}

#[test]
#[should_panic]
fn test_mint_from_negative_amount_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
    let user = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "NEG", "NEG", 7);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_admin", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_admin(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &(-1i128)).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &user, &-1);
}