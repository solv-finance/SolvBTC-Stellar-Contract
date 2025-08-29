#![cfg(test)]

extern crate std;
use crate::fungible_token::{FungibleTokenContract, FungibleTokenContractClient};
use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    Address, Env, String, IntoVal, Bytes, BytesN,
};

fn create_and_init_token<'a>(
    env: &'a Env,
    admin: &'a Address,
    name: &'a str,
    symbol: &'a str,
    decimals: u32,
) -> FungibleTokenContractClient<'a> {
    // For testing, we can use the same admin for all roles, 
    // but in production, these should be different addresses
    let minter_manager = admin.clone();
    let blacklist_manager = admin.clone();
    
    // Register contract with constructor arguments
    let contract_address = env.register(
        FungibleTokenContract, 
        (
            admin,
            &minter_manager,
            &blacklist_manager,
            String::from_str(env, name),
            String::from_str(env, symbol),
            decimals,
        )
    );
    let client = FungibleTokenContractClient::new(env, &contract_address);
    
    client
}

// Helper function to create token with specific role addresses
fn create_and_init_token_with_roles<'a>(
    env: &'a Env,
    admin: &'a Address,
    minter_manager: &'a Address,
    blacklist_manager: &'a Address,
    name: &'a str,
    symbol: &'a str,
    decimals: u32,
) -> FungibleTokenContractClient<'a> {
    // Register contract with all role addresses specified
    let contract_address = env.register(
        FungibleTokenContract, 
        (
            admin,
            minter_manager,
            blacklist_manager,
            String::from_str(env, name),
            String::from_str(env, symbol),
            decimals,
        )
    );
    let client = FungibleTokenContractClient::new(env, &contract_address);
    
    client
}

#[test]
fn test_constructor_initialization() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "MyToken", 
        "MTK", 
        7
    );
    
    // Verify initialization values
    assert_eq!(client.name(), String::from_str(&env, "MyToken"));
    assert_eq!(client.symbol(), String::from_str(&env, "MTK"));
    assert_eq!(client.decimals(), 7);
    assert_eq!(client.get_admin(), owner);
}

#[test]
fn test_mint() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "BTC", "BTC", 7);

    // Add minter
    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "add_minter_by_manager",
            args: (&minter,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.add_minter_by_manager(&minter);

    // Mint tokens
    env.mock_auths(&[MockAuth {
        address: &minter,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "mint_from",
            args: (&minter, &user, &100i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.mint_from(&minter, &user, &100);

    assert_eq!(client.balance(&user), 100);
    assert_eq!(client.total_supply(), 100);
}

#[test]
#[should_panic(expected = "Error(Contract, #150)")]
fn test_mint_unauthorized_should_panic() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);
    let not_minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "BTC", "BTC", 7);

    // Try to mint without being a minter - should panic
    env.mock_auths(&[MockAuth {
        address: &not_minter,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "mint_from",
            args: (&not_minter, &user, &100i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.mint_from(&not_minter, &user, &100);
}

#[test]
fn test_constructor_sets_roles() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "Test", "TST", 6);
    
    // Test minter list (should be empty initially)
    let minter_list = client.get_minters();
    assert_eq!(minter_list.len(), 0);
    
    // Test blacklist (should be empty initially)
    assert!(!client.is_blacklisted(&owner));
    assert!(!client.is_blacklisted(&Address::generate(&env)));
}

#[test]
fn test_transfer() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "MT", "MT", 7);

    // Mint tokens to Alice
    client.add_minter_by_manager(&minter);
    client.mint_from(&minter, &alice, &100);

    // Transfer from Alice to Bob
    client.transfer(&alice, &bob, &40);

    assert_eq!(client.balance(&alice), 60);
    assert_eq!(client.balance(&bob), 40);
}

#[test]
fn test_transfer_from() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let spender = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "MT", "MT", 7);

    // Mint tokens to Alice
    client.add_minter_by_manager(&minter);
    client.mint_from(&minter, &alice, &100);

    // Alice approves spender
    client.approve(&alice, &spender, &50, &1000000);
    assert_eq!(client.allowance(&alice, &spender), 50);

    // Spender transfers from Alice to Bob
    client.transfer_from(&spender, &alice, &bob, &30);

    assert_eq!(client.balance(&alice), 70);
    assert_eq!(client.balance(&bob), 30);
    assert_eq!(client.allowance(&alice, &spender), 20);
}

#[test]
fn test_burn() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "BT", "BT", 7);

    // Mint tokens to Alice
    client.add_minter_by_manager(&minter);
    client.mint_from(&minter, &alice, &100);

    // Alice burns her tokens
    client.burn(&alice, &30);

    assert_eq!(client.balance(&alice), 70);
    assert_eq!(client.total_supply(), 70);
}

#[test]
fn test_approve_and_allowance() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "AT", "AT", 7);

    // Alice approves Bob
    client.approve(&alice, &bob, &100, &1000000);
    assert_eq!(client.allowance(&alice, &bob), 100);

    // Update approval
    client.approve(&alice, &bob, &200, &1000000);
    assert_eq!(client.allowance(&alice, &bob), 200);
}

#[test]
fn test_blacklist_operations() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "BL", "BL", 7);

    // Add minter and mint tokens
    client.add_minter_by_manager(&minter);
    client.mint_from(&minter, &alice, &100);

    // Add Alice to blacklist
    client.add_to_blacklist(&owner, &alice);
    assert!(client.is_blacklisted(&alice));

    // Remove Alice from blacklist
    client.remove_from_blacklist(&owner, &alice);
    assert!(!client.is_blacklisted(&alice));
}

#[test]
#[should_panic(expected = "Error(Contract, #156)")]
fn test_transfer_from_blacklisted_should_panic() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "BL", "BL", 7);

    // Add minter and mint tokens to Alice
    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "add_minter_by_manager",
            args: (&minter,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.add_minter_by_manager(&minter);

    env.mock_auths(&[MockAuth {
        address: &minter,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "mint_from",
            args: (&minter, &alice, &100i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.mint_from(&minter, &alice, &100);

    // Add Alice to blacklist
    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "add_to_blacklist",
            args: (&owner, &alice).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.add_to_blacklist(&owner, &alice);

    // Try to transfer from blacklisted Alice - should panic
    env.mock_auths(&[MockAuth {
        address: &alice,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "transfer",
            args: (&alice, &bob, &10i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.transfer(&alice, &bob, &10);
}

#[test]
fn test_pause_and_unpause() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "PT", "PT", 7);

    // Pause contract
    assert!(!client.paused());
    client.pause(&owner);
    assert!(client.paused());

    // Unpause contract
    client.unpause(&owner);
    assert!(!client.paused());
}

#[test]
#[should_panic(expected = "Error(Contract, #1000)")]
fn test_transfer_when_paused_should_panic() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let minter = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "PT", "PT", 7);

    // Add minter and mint tokens to Alice
    client.add_minter_by_manager(&minter);
    client.mint_from(&minter, &alice, &100);

    // Pause the contract
    client.pause(&owner);

    // Try to transfer - should panic
    client.transfer(&alice, &bob, &10);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_pause_not_owner_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "PO", "PO", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "pause", args: (&not_owner,).into_val(&env), sub_invokes: &[] } }]);
	client.pause(&not_owner);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_unpause_not_owner_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "PO", "PO", 7);
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
		invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] },
	}]);
	client.add_minter_by_manager(&minter);
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
	env.mock_auths(&[MockAuth {
		address: &owner,
		invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] },
	}]);
	client.remove_minter_by_manager(&minter);
	assert!(!client.is_minter(&minter));
}

#[test]
fn test_get_minters() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let minter1 = Address::generate(&env);
	let minter2 = Address::generate(&env);
	let minter3 = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MV", "MV", 7);

	// add multiple minters
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter1,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter1);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter2,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter2);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter3,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter3);

	// get minters and verify
	let minters = client.get_minters();
	assert_eq!(minters.len(), 3);
}

#[test]
fn test_too_many_minters_and_duplicate_and_remove_nonexistent() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "TM", "TM", 7);

	// add 10 minters (max allowed)
	for _i in 0..10 {
		let minter = Address::generate(&env);
		env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
		client.add_minter_by_manager(&minter);
	}

	assert_eq!(client.get_minters().len(), 10);
}

#[test]
#[should_panic(expected = "Error(Contract, #159)")]
fn test_add_duplicate_minter_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "DM", "DM", 7);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
}

#[test]
#[should_panic(expected = "Error(Contract, #157)")]
fn test_add_eleventh_minter_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "EM", "EM", 7);
	for _i in 0..10 {
		let minter = Address::generate(&env);
		env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
		client.add_minter_by_manager(&minter);
	}
	let minter11 = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter11,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter11);
}

#[test]
#[should_panic(expected = "Error(Contract, #158)")]
fn test_remove_nonexistent_minter_should_panic() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "RM", "RM", 7);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.remove_minter_by_manager(&minter);
}

#[test]
fn test_burn_blacklisted_tokens_by_admin() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let blacklisted = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BBT", "BBT", 7);

	// mint to blacklisted user
	let minter = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &blacklisted, &100i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &blacklisted, &100);

	// blacklist the user
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &blacklisted).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &blacklisted);

	// burn blacklisted tokens - this burns ALL tokens from the blacklisted address
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "burn_blacklisted_tokens_by_admin", args: (&blacklisted,).into_val(&env), sub_invokes: &[] } }]);
	client.burn_blacklisted_tokens_by_admin(&blacklisted);
	assert_eq!(client.balance(&blacklisted), 0);
	assert_eq!(client.total_supply(), 0);
}

#[test]
fn test_get_blacklisted_addresses() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let a1 = Address::generate(&env);
	let a2 = Address::generate(&env);
	let a3 = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BL", "BL", 7);

	// blacklist multiple addresses
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &a1).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &a1);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &a2).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &a2);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &a3).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &a3);

	// verify blacklisted addresses (can only check individually)
	assert!(client.is_blacklisted(&a1));
	assert!(client.is_blacklisted(&a2));
	assert!(client.is_blacklisted(&a3));

	// remove one
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_from_blacklist", args: (&owner, &a2).into_val(&env), sub_invokes: &[] } }]);
	client.remove_from_blacklist(&owner, &a2);
	// verify a2 is no longer blacklisted
	assert!(!client.is_blacklisted(&a2));
	assert!(client.is_blacklisted(&a1));
	assert!(client.is_blacklisted(&a3));
}

#[test]
fn test_blacklist_scenario() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env); // blacklist manager
	let a = Address::generate(&env);
	let b = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token_with_roles(&env, &owner, &owner, &mgr, "BS", "BS", 7);

	// mint to a
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &100i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &100);

	// blacklist a
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&mgr, &a).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&mgr, &a);
	assert!(client.is_blacklisted(&a));

	// remove from blacklist
	env.mock_auths(&[MockAuth { address: &mgr, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_from_blacklist", args: (&mgr, &a).into_val(&env), sub_invokes: &[] } }]);
	client.remove_from_blacklist(&mgr, &a);
	assert!(!client.is_blacklisted(&a));

	// now can transfer
	env.mock_auths(&[MockAuth { address: &a, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "transfer", args: (&a, &b, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.transfer(&a, &b, &10);
	assert_eq!(client.balance(&a), 90);
}

#[test]
fn test_multiple_blacklist_operations() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let minter = Address::generate(&env);
	let a = Address::generate(&env);
	let b = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "MB", "MB", 7);

	// mint to multiple users
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &50i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &50);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &b, &30i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &b, &30);

	// blacklist a and b
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &a).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &a);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &b).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &b);
	assert!(client.is_blacklisted(&a));
	assert!(client.is_blacklisted(&b));

	// remove a from blacklist
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_from_blacklist", args: (&owner, &a).into_val(&env), sub_invokes: &[] } }]);
	client.remove_from_blacklist(&owner, &a);
	assert!(!client.is_blacklisted(&a));
	assert!(client.is_blacklisted(&b));
}

#[test]
fn test_view_functions() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "VIEW", "VW", 9);

	assert_eq!(client.name(), String::from_str(&env, "VIEW"));
	assert_eq!(client.symbol(), String::from_str(&env, "VW"));
	assert_eq!(client.decimals(), 9);
	assert_eq!(client.total_supply(), 0);
	assert_eq!(client.balance(&owner), 0);
	assert!(!client.paused());
	assert!(!client.is_blacklisted(&owner));
	assert_eq!(client.get_minters().len(), 0);
	assert_eq!(client.get_admin(), owner);
}

#[test]
fn test_admin_functions() {
    let env = Env::default();
	let owner = Address::generate(&env);
	let new_admin = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "ADM", "AD", 7);

	assert_eq!(client.get_admin(), owner);

	// transfer ownership - stellar_ownable uses two-step process
	let live_until = 1000000u32;
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "transfer_ownership", args: (&new_admin, &live_until).into_val(&env), sub_invokes: &[] } }]);
	client.transfer_ownership(&new_admin, &live_until);
	
	// New owner must accept the ownership
	env.mock_auths(&[MockAuth { address: &new_admin, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "accept_ownership", args: ().into_val(&env), sub_invokes: &[] } }]);
	client.accept_ownership();
	
	assert_eq!(client.get_admin(), new_admin);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_add_minter_unauthorized_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "AU", "AU", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_remove_minter_unauthorized_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "RU", "RU", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.remove_minter_by_manager(&minter);
}

#[test]
#[should_panic(expected = "Error(Contract, #150)")]
fn test_add_to_blacklist_unauthorized_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let user = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "AB", "AB", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&not_owner, &user).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&not_owner, &user);
}

#[test]
#[should_panic(expected = "Error(Contract, #150)")]
fn test_remove_from_blacklist_unauthorized_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let user = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "RB", "RB", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "remove_from_blacklist", args: (&not_owner, &user).into_val(&env), sub_invokes: &[] } }]);
	client.remove_from_blacklist(&not_owner, &user);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_burn_blacklisted_tokens_unauthorized_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let not_owner = Address::generate(&env);
	let user = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "BU", "BU", 7);
	env.mock_auths(&[MockAuth { address: &not_owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "burn_blacklisted_tokens_by_admin", args: (&user,).into_val(&env), sub_invokes: &[] } }]);
	client.burn_blacklisted_tokens_by_admin(&user);
}

#[test]
#[should_panic(expected = "Error(Contract, #156)")]
fn test_transfer_to_blacklisted_recipient_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let user = Address::generate(&env);
	let recipient = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "TB", "TB", 7);

	// mint to user
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &user, &10);

	// blacklist recipient
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_to_blacklist", args: (&owner, &recipient).into_val(&env), sub_invokes: &[] } }]);
	client.add_to_blacklist(&owner, &recipient);

	// transfer to blacklisted recipient should panic
	env.mock_auths(&[MockAuth { address: &user, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "transfer", args: (&user, &recipient, &1i128).into_val(&env), sub_invokes: &[] } }]);
	client.transfer(&user, &recipient, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #156)")]
fn test_transfer_from_with_blacklisted_spender_should_panic() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let mgr = Address::generate(&env);
	let user = Address::generate(&env);
	let spender = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token_with_roles(&env, &owner, &owner, &mgr, "TF", "TF", 7);

	// mint to user
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
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
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
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

	// mint to a
	let minter = Address::generate(&env);
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &a, &10i128).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &a, &10);

	// try to burn when not blacklisted - should panic
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "burn_blacklisted_tokens_by_admin", args: (&a,).into_val(&env), sub_invokes: &[] } }]);
	client.burn_blacklisted_tokens_by_admin(&a);
}

#[test]
fn test_pause_state_transition() {
	let env = Env::default();
	let owner = Address::generate(&env);
	let a = Address::generate(&env);
	let b = Address::generate(&env);
	let minter = Address::generate(&env);
	let client = create_and_init_token(&env, &owner, "PS", "PS", 7);

	// mint initially
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
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
	env.mock_auths(&[MockAuth { address: &owner, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "add_minter_by_manager", args: (&minter,).into_val(&env), sub_invokes: &[] } }]);
	client.add_minter_by_manager(&minter);
	env.mock_auths(&[MockAuth { address: &minter, invoke: &MockAuthInvoke { contract: &client.address, fn_name: "mint_from", args: (&minter, &user, &(-1i128)).into_val(&env), sub_invokes: &[] } }]);
	client.mint_from(&minter, &user, &-1);
}

#[test]
fn test_is_minter_manager() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let random_user = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Test is_minter_manager function
    assert!(client.is_minter_manager(&minter_manager));
    assert!(!client.is_minter_manager(&owner)); // owner is not minter manager in this test
    assert!(!client.is_minter_manager(&blacklist_manager));
    assert!(!client.is_minter_manager(&random_user));
}

#[test]
fn test_get_minter_manager() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Test get_minter_manager function
    let retrieved_manager = client.get_minter_manager();
    assert_eq!(retrieved_manager, minter_manager);
}

#[test]
fn test_minter_manager_same_as_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    
    // When using create_and_init_token, admin is also minter_manager
    let client = create_and_init_token(&env, &admin, "TestToken", "TTK", 8);
    
    assert!(client.is_minter_manager(&admin));
    let manager = client.get_minter_manager();
    assert_eq!(manager, admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #150)")]
fn test_require_blacklist_manager_with_wrong_address_should_panic() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let wrong_manager = Address::generate(&env);
    let user_to_blacklist = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Try to add to blacklist with wrong address (not blacklist_manager) - should panic
    env.mock_auths(&[MockAuth { 
        address: &wrong_manager, 
        invoke: &MockAuthInvoke { 
            contract: &client.address, 
            fn_name: "add_to_blacklist", 
            args: (&wrong_manager, &user_to_blacklist).into_val(&env), 
            sub_invokes: &[] 
        } 
    }]);
    client.add_to_blacklist(&wrong_manager, &user_to_blacklist);
}

#[test]
fn test_blacklist_manager_operations() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let user_to_blacklist = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Blacklist manager can add to blacklist
    env.mock_auths(&[MockAuth { 
        address: &blacklist_manager, 
        invoke: &MockAuthInvoke { 
            contract: &client.address, 
            fn_name: "add_to_blacklist", 
            args: (&blacklist_manager, &user_to_blacklist).into_val(&env), 
            sub_invokes: &[] 
        } 
    }]);
    client.add_to_blacklist(&blacklist_manager, &user_to_blacklist);
    assert!(client.is_blacklisted(&user_to_blacklist));
    
    // Blacklist manager can remove from blacklist
    env.mock_auths(&[MockAuth { 
        address: &blacklist_manager, 
        invoke: &MockAuthInvoke { 
            contract: &client.address, 
            fn_name: "remove_from_blacklist", 
            args: (&blacklist_manager, &user_to_blacklist).into_val(&env), 
            sub_invokes: &[] 
        } 
    }]);
    client.remove_from_blacklist(&blacklist_manager, &user_to_blacklist);
    assert!(!client.is_blacklisted(&user_to_blacklist));
}

#[test]
fn test_is_blacklist_manager() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let random_user = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Test is_blacklist_manager
    assert!(client.is_blacklist_manager(&blacklist_manager));
    assert!(!client.is_blacklist_manager(&owner));
    assert!(!client.is_blacklist_manager(&minter_manager));
    assert!(!client.is_blacklist_manager(&random_user));
}

// ==================== Upgrade Tests ====================

// Use workspace root optimized wasm for FT
const FT_WASM_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/wasm32-unknown-unknown/optimized/fungible_token.wasm"
));

#[test]
fn test_ft_upgrade_success() {
    let env = Env::default();
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "UPG", "UPG", 7);

    let wasm_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, FT_WASM_BYTES));

    client.upgrade(&wasm_hash);

    // Verify still functional
    assert_eq!(client.decimals(), 7);
}

#[test]
#[should_panic]
fn test_ft_upgrade_with_unuploaded_hash_should_panic() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "UPG", "UPG", 7);

    let fake = BytesN::from_array(&env, &[3u8; 32]);
    client.upgrade(&fake);
}

#[test]
#[should_panic]
fn test_ft_upgrade_requires_owner_should_panic() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let client = create_and_init_token(&env, &owner, "UPG", "UPG", 7);

    let wasm_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, FT_WASM_BYTES));

    // No auth mocked → only_owner should fail
    client.upgrade(&wasm_hash);
}

#[test]
fn test_get_blacklist_manager() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Get blacklist manager
    let retrieved_manager = client.get_blacklist_manager();
    assert_eq!(retrieved_manager, blacklist_manager);
}

#[test]
fn test_set_blacklist_manager() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let new_blacklist_manager = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Initially should be the original blacklist_manager
    assert!(client.is_blacklist_manager(&blacklist_manager));
    assert_eq!(client.get_blacklist_manager(), blacklist_manager);
    
    // Change blacklist manager (only owner can do this)
    client.set_blacklist_manager(&new_blacklist_manager);
    
    // Verify the change
    assert!(!client.is_blacklist_manager(&blacklist_manager));
    assert!(client.is_blacklist_manager(&new_blacklist_manager));
    assert_eq!(client.get_blacklist_manager(), new_blacklist_manager);
}

#[test]
fn test_set_minter_manager() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let new_minter_manager = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Initially should be the original minter_manager
    assert!(client.is_minter_manager(&minter_manager));
    assert_eq!(client.get_minter_manager(), minter_manager);
    
    // Change minter manager (only owner can do this)
    client.set_minter_manager(&new_minter_manager);
    
    // Verify the change
    assert!(!client.is_minter_manager(&minter_manager));
    assert!(client.is_minter_manager(&new_minter_manager));
    assert_eq!(client.get_minter_manager(), new_minter_manager);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_non_minter_manager_cannot_add_minter() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let minter_manager = Address::generate(&env);
    let blacklist_manager = Address::generate(&env);
    let not_minter_manager = Address::generate(&env);
    let new_minter = Address::generate(&env);
    
    let client = create_and_init_token_with_roles(
        &env, 
        &owner, 
        &minter_manager,
        &blacklist_manager,
        "TestToken", 
        "TTK", 
        8
    );
    
    // Try to add minter with wrong address (not minter_manager) - should panic
    env.mock_auths(&[MockAuth { 
        address: &not_minter_manager, 
        invoke: &MockAuthInvoke { 
            contract: &client.address, 
            fn_name: "add_minter_by_manager", 
            args: (&new_minter,).into_val(&env), 
            sub_invokes: &[] 
        } 
    }]);
    client.add_minter_by_manager(&new_minter);
}