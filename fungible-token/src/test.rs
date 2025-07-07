#![cfg(test)]

extern crate std;
use std::println; 
use soroban_sdk::vec;
use crate::{FungibleToken, FungibleTokenClient};
use soroban_sdk::{
    symbol_short,log,
    testutils::{Address as _, MockAuth, MockAuthInvoke, AuthorizedFunction, AuthorizedInvocation, Events},
    Address, Env, String, IntoVal, Symbol
};

fn create_token_contract(env: &Env) -> (FungibleTokenClient, Address) {
    let contract_address = env.register(FungibleToken, ());
    let client = FungibleTokenClient::new(env, &contract_address);
    (client, contract_address)
}

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Verify initialization results
    assert_eq!(client.name(), String::from_str(&env, "Test Token"));
    assert_eq!(client.symbol(), String::from_str(&env, "TEST"));
    assert_eq!(client.decimals(), 18);
    assert_eq!(client.total_supply(), 0);  // Initial supply is 0
    assert_eq!(client.balance_of(&admin), 0);  // Admin initial balance is 0
    assert_eq!(client.admin(), Some(admin));
    assert!(client.is_initialized());
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_initialize_already_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // First initialization
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Second initialization should panic
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token 2"),
        &String::from_str(&env, "TEST2"),
        &18,
        &admin,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_initialize_invalid_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &19, // Invalid decimal places
        &admin,
    );
}

#[test]
fn test_mint_and_balance() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Mint tokens
    client.mint(&_user, &500);

    assert_eq!(client.balance_of(&_user), 500);
    assert_eq!(client.total_supply(), 500);
}

#[test]
fn test_transfer_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to admin
    client.mint(&admin, &1000);

    // Transfer
    client.transfer(&admin, &_user, &100);

    assert_eq!(client.balance_of(&admin), 900);
    assert_eq!(client.balance_of(&_user), 100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #8)")]
fn test_transfer_invalid_amount_negative() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to admin
    client.mint(&admin, &1000);

    // Try to transfer negative amount
    client.transfer(&admin, &_user, &-100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #8)")]
fn test_transfer_invalid_amount_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to admin
    client.mint(&admin, &1000);

    // Try to transfer zero
    client.transfer(&admin, &_user, &0);
}

#[test]
fn test_approve_and_allowance() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let spender = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Approve
    client.approve(&admin, &spender, &200);
    assert_eq!(client.allowance(&admin, &spender), 200);
}

#[test]
fn test_admin_mint_and_burn() {
    let env = Env::default();
    
    let admin = Address::generate(&env);
    let minter = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    env.mock_auths(&[
        MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "initialize",
                args: (
                    &admin,
                    String::from_str(&env, "Test Token"),
                    String::from_str(&env, "TEST"),
                    18u32,
                    &minter  // Now admin is the minter
                ).into_val(&env),
                sub_invokes: &[],
            },
        },
    ]);

    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &minter,
    );
    // Minter mints some tokens to themselves first
    env.mock_auths(&[
        MockAuth {
            address: &minter,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "mint",
                args: (&minter, &1000_i128).into_val(&env),
                sub_invokes: &[],
            },
        },
    ]);

    client.mint(&minter, &1000);
    assert_eq!(client.balance_of(&minter), 1000);
    // Minter burns tokens (from their own account)
    env.mock_auths(&[
        MockAuth {
            address: &minter,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "burn",
                args: (&500_i128,).into_val(&env),  // Use tuple format
                sub_invokes: &[],
            },
        },
    ]);

    client.burn(&500);  // Burn 500 tokens from minter account
    assert_eq!(client.balance_of(&minter), 500);  // Minter has 500 tokens remaining
    
}

#[test]
fn test_pause_unpause() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (client, _contract_address) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
            &admin,
            &String::from_str(&env, "Test Token"),
            &String::from_str(&env, "TEST"),
            &18,
            &admin,
        );

    // Verify initial state is not paused
    assert!(!client.is_paused());
    
    // Pause contract - OpenZeppelin's pause function calls admin.require_auth()
    client.pause();
    
    // Verify contract is paused
    assert!(client.is_paused());

    // Unpause contract - OpenZeppelin's unpause function calls admin.require_auth()
    client.unpause();
    
    // Verify contract is unpaused
    assert!(!client.is_paused());
}

#[test]
fn test_transfer_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Transfer admin permission
    client.transfer_admin(&new_admin);

    assert_eq!(client.admin(), Some(new_admin));
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_transfer_when_paused() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to admin
    client.mint(&admin, &1000);

    // Pause contract
    client.pause();

    // Try to transfer should fail
    client.transfer(&admin, &_user, &100);
}

#[test]
fn test_data_examples() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    let spender = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "MyToken"),
        &String::from_str(&env, "MTK"),
        &18,
        &admin,
    );

    // Mint tokens
    client.mint(&user1, &1000);
    client.mint(&user2, &500);

    // Approve
    client.approve(&user1, &spender, &200);

    // Transfer
    client.transfer(&user1, &user2, &100);

    // Proxy transfer
    client.transfer_from(&spender, &user1, &user2, &50);

    // Verify final state
    assert_eq!(client.balance_of(&user1), 850); // 1000 - 100 - 50
    assert_eq!(client.balance_of(&user2), 650); // 500 + 100 + 50 - 25
    assert_eq!(client.total_supply(), 1500); // 1000 + 500 - 25
    assert_eq!(client.allowance(&user1, &spender), 150); // 200 - 50
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_mint_when_paused() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Pause contract
    client.pause();

    // Try to mint should fail
    client.mint(&_user, &100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #8)")]
fn test_mint_invalid_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Try to mint negative tokens
    client.mint(&_user, &-100);
}

#[test]
fn test_mint_unauthorized_non_admin() {
    let env = Env::default();
    
    let admin = Address::generate(&env);
    let _non_admin_user = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (client, _contract_address) = create_token_contract(&env);

    // Initialize contract (using admin permission)
    env.mock_all_auths();
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Clear authorization records from initialization
    // env.mock_all_auths();

    println!("admin: {:?}", admin);
    println!("non_admin_user: {:?}", _non_admin_user);
    println!("recipient: {:?}", recipient);
    println!("client.address: {:?}", client.address);
    println!("auth: {:?}", env.auths());
    client.mint(&recipient,&100);
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(), 
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    client.address.clone(),
                    symbol_short!("mint"),
                    (recipient.clone(), 100_i128).into_val(&env),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
}

#[test]
fn test_blacklist_add_remove() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Verify user is not in blacklist
    assert!(!client.is_blacklisted(&_user));

    // Add user to blacklist
    client.add_to_blacklist(&_user);
    assert!(client.is_blacklisted(&_user));

    // Remove user from blacklist
    client.remove_from_blacklist(&_user);
    assert!(!client.is_blacklisted(&_user));
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #9)")]
fn test_blacklist_transfer_from_blocked() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let blacklisted_user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to admin
    client.mint(&admin, &1000);

    // Add user to blacklist
    client.add_to_blacklist(&blacklisted_user);

    // Try to transfer to blacklisted user should fail
    client.transfer(&admin, &blacklisted_user, &100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #9)")]
fn test_blacklist_transfer_to_blocked() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let blacklisted_user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to blacklisted user
    client.mint(&blacklisted_user, &1000);

    // Add user to blacklist
    client.add_to_blacklist(&blacklisted_user);

    // Try to transfer from blacklisted user should fail
    client.transfer(&blacklisted_user, &_user, &100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #9)")]
fn test_blacklist_approve_blocked() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let spender = Address::generate(&env);
    let blacklisted_user = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Add user to blacklist
    client.add_to_blacklist(&blacklisted_user);

    // Try to approve blacklisted user should fail
    client.approve(&blacklisted_user, &spender, &100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #9)")]
fn test_blacklist_transfer_from_spender_blocked() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let blacklisted_spender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to user
    client.mint(&_user, &1000);

    // Approve to spender
    client.approve(&_user, &blacklisted_spender, &200);

    // Add spender to blacklist
    client.add_to_blacklist(&blacklisted_spender);

    // Try to proxy transfer should fail
    client.transfer_from(&blacklisted_spender, &_user, &recipient, &100);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #9)")]
fn test_blacklist_transfer_from_recipient_blocked() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let _user = Address::generate(&env);
    let spender = Address::generate(&env);
    let blacklisted_recipient = Address::generate(&env);
    let (client, _) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // First mint some tokens to user
    client.mint(&_user, &1000);

    // Approve to spender
    client.approve(&_user, &spender, &200);

    // Add recipient to blacklist
    client.add_to_blacklist(&blacklisted_recipient);

    // Try to proxy transfer to blacklisted user should fail
    client.transfer_from(&spender, &_user, &blacklisted_recipient, &100);
}

#[test]
fn test_mint_event_detailed() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (client, contract_id) = create_token_contract(&env);

    // Initialize contract
    client.initialize(
        &admin,
        &String::from_str(&env, "Test Token"),
        &String::from_str(&env, "TEST"),
        &18,
        &admin,
    );

    // Mint tokens
    client.mint(&recipient, &100);

    // Verify event structure
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "mint"), &recipient).into_val(&env),
                (100i128).into_val(&env)
            ),
            (
                contract_id,
                (Symbol::new(&env, "mint"),).into_val(&env),
                (admin.clone(), recipient.clone(), 100i128).into_val(&env)
            ),
        ]
);
} 
