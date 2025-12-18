#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events, MockAuth, MockAuthInvoke},
    contract, contractimpl, Address, Bytes, BytesN, Env, Symbol, IntoVal,
};
use secp256k1::{Message, SecretKey, PublicKey, Secp256k1};
use sha3::{Digest, Keccak256};
use rand::thread_rng;
use crate::test::std::string::ToString;

// ==================== Mock Oracle ====================
#[contract]
pub struct MockOracle;

#[contractimpl]
impl MockOracle {
    pub fn get_nav(env: Env) -> i128 {
        env.storage().instance().get(&Symbol::new(&env, "nav")).unwrap_or(100_000_000i128) // Default 1.0 (8 decimals)
    }
    pub fn get_nav_decimals(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "decimals"))
            .unwrap_or(8)
    }
    pub fn set_nav_value(env: Env, nav: i128) {
         env.storage().instance().set(&Symbol::new(&env, "nav"), &nav);
    }
    // Helper to set different decimals
    pub fn set_decimals_val(env: Env, decimals: u32) {
        env.storage().instance().set(&Symbol::new(&env, "decimals"), &decimals);
    }
}

// ==================== Mock Token ====================
#[contract]
pub struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn balance(_env: Env, _account: Address) -> i128 { 
        1_000_000_000_000_000 // Always rich
    }
    pub fn decimals(env: Env) -> u32 { 
        env.storage().instance().get(&Symbol::new(&env, "decimals")).unwrap_or(18)
    }
    // Different name to avoid conflict
    pub fn set_token_decimals(env: Env, decimals: u32) {
        env.storage().instance().set(&Symbol::new(&env, "decimals"), &decimals);
    }
    pub fn mint(_env: Env, _to: Address, _amount: i128) {}
    pub fn burn(_env: Env, _from: Address, _amount: i128) {}
    
    // Stub other required methods
    pub fn approve(_env: Env, _owner: Address, _spender: Address, _amount: i128, _live: u32) {}
    pub fn transfer(_env: Env, _from: Address, _to: Address, _amount: i128) {}
    pub fn transfer_from(_env: Env, _spender: Address, _from: Address, _to: Address, _amount: i128) {}
    pub fn burn_from(_env: Env, _spender: Address, _from: Address, _amount: i128) {}
    pub fn mint_from(_env: Env, _from: Address, _to: Address, _amount: i128) {}
}

// ==================== Helper Functions ====================

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());
    (secret_key, public_key)
}

fn get_signer_cap_key(env: &Env, public_key: &PublicKey) -> BytesN<65> {
    // Serialize to 65 bytes uncompressed
    let serialized = public_key.serialize_uncompressed();
    BytesN::from_array(env, &serialized)
}

fn sign_message(env: &Env, secret_key: &SecretKey, message: &Bytes) -> BytesN<65> {
    // 1. Calculate Personal Sign Hash
    // keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
    let mut prefix = std::vec::Vec::new();
    prefix.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    prefix.extend_from_slice(message.len().to_string().as_bytes());
    
    let mut full_msg = prefix;
    let mut msg_bytes = std::vec![0u8; message.len() as usize];
    message.copy_into_slice(&mut msg_bytes);
    full_msg.extend_from_slice(&msg_bytes);

    let mut hasher = Keccak256::new();
    hasher.update(&full_msg);
    let hash = hasher.finalize();

    // 2. Sign
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&hash).unwrap();
    let signature = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (rec_id, sig_bytes_compact) = signature.serialize_compact();
    
    // 3. Construct 65-byte signature (R + S + V)
    let rec_id_byte = rec_id.to_i32() as u8; // 0-3
    let mut sig_bytes = [0u8; 65];
    sig_bytes[0..64].copy_from_slice(&sig_bytes_compact);
    sig_bytes[64] = rec_id_byte + 27; // Ethereum style v (27 or 28)

    BytesN::from_array(env, &sig_bytes)
}

// Helper to construct the mint message exactly as the contract does

fn create_test_setup() -> (Env, SolvBTCBridgeClient<'static>, Address, MockTokenClient<'static>, MockOracleClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let token_id = env.register(MockToken, ());
    let token_client = MockTokenClient::new(&env, &token_id);
    
    let oracle_id = env.register(MockOracle, ());
    let oracle_client = MockOracleClient::new(&env, &oracle_id);

    // Register bridge and let host invoke __constructor(&Env, admin, token, oracle)
    let bridge_id = env.register(
        SolvBTCBridge,
        (&admin, &token_id, &oracle_id),
    );
    let bridge_client = SolvBTCBridgeClient::new(&env, &bridge_id);

    (env, bridge_client, admin, token_client, oracle_client, user)
}

// ==================== Tests ====================

#[test]
fn test_register_bridge_only() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let token_id = env.register(MockToken, ());
    let oracle_id = env.register(MockOracle, ());

    // Just ensure registering the bridge with constructor args does not panic
    let _bridge_id = env.register(
        SolvBTCBridge,
        (&admin, &token_id, &oracle_id),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #411)")] // InvalidDecimals
fn test_constructor_rejects_invalid_decimals_bridge() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let token_id = env.register(MockToken, ());
    let token_client = MockTokenClient::new(&env, &token_id);
    // Set an invalid token decimals (> 18) before bridge initialization.
    token_client.set_token_decimals(&19);

    let oracle_id = env.register(MockOracle, ());

    let _bridge_id = env.register(
        SolvBTCBridge,
        (&admin, &token_id, &oracle_id),
    );
}

#[test]
fn test_mint_success() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    // 1. Setup Signer
    let (secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    // Large cap to comfortably cover mint amount for 1 BTC at NAV=1
    let cap = 1_000_000_000_000_000_000_000i128;
    bridge.set_signer_cap(&signer_key, &cap);

    // 2. Prepare Data
    let btc_tx_hash = Bytes::from_slice(&env, &[0xab; 64]); // 64-byte hex string
    let btc_amount = 100_000_000i128; // 1 BTC
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 100_000_000i128; // 1.0
    let nav_str = Bytes::from_slice(&env, b"1.0");
    
    // Calculate OP_RETURN Hash
    let op_return_hash =
        SolvBTCBridge::compute_op_return_hash(&env, &token.address, &user);

    // 3. Sign
    // Convert OP_RETURN hash to hex as done in contract
    let op_hash_hex = SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);
    let message = SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        btc_amount,
        &op_hash_hex,
        &nav_str,
        nav,
        &user,
        &token.address,
    );
    let signature = sign_message(&env, &secret_key, &message);

    // 4. Mint
    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        // &op_return_hash, // Removed
        &btc_amount,
        &btc_amount_str,
        &nav,
        &nav_str,
        &token.address
    );

    // Verify Event
    let events = env.events().all();
    // Look for the last event being Mint
    let last_event = events.last().unwrap();
    // last_event is (ContractId, Topics, Data)
    // topics is Vec<Val>
    assert_eq!(last_event.1.len(), 3); // topics: mint, from, token
}

#[test]
fn test_mint_accepts_hex_string_btc_tx_hash() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();

    let (secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    bridge.set_signer_cap(&signer_key, &1_000_000_000_000_000_000_000i128);

    // 64-byte hex string (UTF-8 bytes)
    let btc_tx_hash = Bytes::from_slice(
        &env,
        b"c83c3cb20fc2b222a2707033ae52995454fcc3f70803c5ca33ebbafb5fd00687",
    );
    let btc_amount = 100_000_000i128;
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 100_000_000i128;
    let nav_str = Bytes::from_slice(&env, b"1.0");

    let op_return_hash = SolvBTCBridge::compute_op_return_hash(&env, &token.address, &user);
    let op_hash_hex = SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);
    let message = SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        btc_amount,
        &op_hash_hex,
        &nav_str,
        nav,
        &user,
        &token.address,
    );
    let signature = sign_message(&env, &secret_key, &message);

    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        &btc_amount,
        &btc_amount_str,
        &nav,
        &nav_str,
        &token.address,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")] // InvalidAmount
fn test_mint_invalid_amount() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    // Dummy data
    let signature = BytesN::from_array(&env, &[0u8; 65]);
    let btc_tx_hash = Bytes::from_slice(&env, &[0u8; 64]); // 64-byte hex string
    
    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        &0, // Amount 0
        &Bytes::from_slice(&env, b"0"),
        &100,
        &Bytes::from_slice(&env, b"1"),
        &token.address
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #402)")] // InvalidNav
fn test_mint_invalid_nav() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    let signature = BytesN::from_array(&env, &[0u8; 65]);
    let btc_tx_hash = Bytes::from_slice(&env, &[0u8; 64]); // 64-byte hex string
    
    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        &100,
        &Bytes::from_slice(&env, b"1"),
        &0, // Nav 0
        &Bytes::from_slice(&env, b"0"),
        &token.address
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #404)")] // TokenNotSupported
fn test_mint_wrong_token() {
    let (env, bridge, _admin, _token, _oracle, user) = create_test_setup();
    let wrong_token = Address::generate(&env);
    
    let signature = BytesN::from_array(&env, &[0u8; 65]);
    let btc_tx_hash = Bytes::from_slice(&env, &[0u8; 64]); // 64-byte hex string
    
    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        &100,
        &Bytes::from_slice(&env, b"1"),
        &100,
        &Bytes::from_slice(&env, b"1"),
        &wrong_token
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #408)")] // InvalidData
fn test_mint_invalid_btc_tx_hash_length() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();

    let signature = BytesN::from_array(&env, &[0u8; 65]);
    let btc_tx_hash = Bytes::from_slice(&env, &[0u8; 32]);

    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        &100,
        &Bytes::from_slice(&env, b"1"),
        &100,
        &Bytes::from_slice(&env, b"1"),
        &token.address,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #405)")] // TxAlreadyUsed
fn test_mint_replay() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    // Setup valid mint
    let (secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    // Large cap so replay test is not blocked by cap
    bridge.set_signer_cap(&signer_key, &1_000_000_000_000_000_000_000i128);

    let btc_tx_hash = Bytes::from_slice(&env, &[0x11; 64]); // 64-byte hex string
    let btc_amount = 100_000_000i128;
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 100_000_000i128;
    let nav_str = Bytes::from_slice(&env, b"1.0");
    
    let op_return_hash =
        SolvBTCBridge::compute_op_return_hash(&env, &token.address, &user);

    let op_hash_hex = SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);
    let message = SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        btc_amount,
        &op_hash_hex,
        &nav_str,
        nav,
        &user,
        &token.address,
    );
    let signature = sign_message(&env, &secret_key, &message);

    // 1st Mint
    bridge.mint(&user, &signature, &btc_tx_hash, &btc_amount, &btc_amount_str, &nav, &nav_str, &token.address);
    
    // 2nd Mint (Replay)
    bridge.mint(&user, &signature, &btc_tx_hash, &btc_amount, &btc_amount_str, &nav, &nav_str, &token.address);
}

#[test]
#[should_panic(expected = "Error(Contract, #407)")] // SignerCapExceeded
fn test_mint_cap_exceeded() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    let (secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    // Cap = 1 satoshi
    bridge.set_signer_cap(&signer_key, &1);

    let btc_tx_hash = Bytes::from_slice(&env, &[0x22; 64]); // 64-byte hex string
    let btc_amount = 100_000_000i128; // 1 BTC
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 100_000_000i128;
    let nav_str = Bytes::from_slice(&env, b"1.0");
    
    let op_return_hash =
        SolvBTCBridge::compute_op_return_hash(&env, &token.address, &user);

    let op_hash_hex = SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);
    let message = SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        btc_amount,
        &op_hash_hex,
        &nav_str,
        nav,
        &user,
        &token.address,
    );
    let signature = sign_message(&env, &secret_key, &message);

    bridge.mint(&user, &signature, &btc_tx_hash, &btc_amount, &btc_amount_str, &nav, &nav_str, &token.address);
}

#[test]
#[should_panic(expected = "Error(Contract, #407)")] // SignerCapExceeded (which means unauthorized if cap is 0/missing)
fn test_mint_unauthorized_signer() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    // Key generated but NOT added to bridge
    let (secret_key, _public_key) = generate_keypair();
    
    let btc_tx_hash = Bytes::from_slice(&env, &[0x33; 64]); // 64-byte hex string
    let btc_amount = 100_000_000i128; 
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 100_000_000i128;
    let nav_str = Bytes::from_slice(&env, b"1.0");
    
    let op_return_hash =
        SolvBTCBridge::compute_op_return_hash(&env, &token.address, &user);

    let op_hash_hex = SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);
    let message = SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        btc_amount,
        &op_hash_hex,
        &nav_str,
        nav,
        &user,
        &token.address,
    );
    let signature = sign_message(&env, &secret_key, &message);

    bridge.mint(&user, &signature, &btc_tx_hash, &btc_amount, &btc_amount_str, &nav, &nav_str, &token.address);
}

#[test]
#[should_panic(expected = "Error(Contract, #410)")] // NavOutOfRange
fn test_mint_nav_outdated() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    let (secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    // Large cap so NAV-outdated error is hit instead of cap
    bridge.set_signer_cap(&signer_key, &1_000_000_000_000_000_000_000i128);
    
    // Oracle has 1.0
    // User provides 1.02 (> 1% diff)
    let btc_amount = 100_000_000i128;
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 102_000_000i128; // 1.02
    let nav_str = Bytes::from_slice(&env, b"1.02");
    
    let btc_tx_hash = Bytes::from_slice(&env, &[0x44; 64]); // 64-byte hex string
    let mut op_input = Bytes::new(&env);
    op_input.append(&Bytes::from_slice(&env, b"stellar"));
    op_input.append(&SolvBTCBridge::address_to_bytes(&env, &token.address));
    op_input.append(&SolvBTCBridge::address_to_bytes(&env, &user));
    let op_return_hash = env.crypto().keccak256(&op_input).into();

    let op_hash_hex = SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);
    let message = SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        btc_amount,
        &op_hash_hex,
        &nav_str,
        nav,
        &user,
        &token.address,
    );
    let signature = sign_message(&env, &secret_key, &message);

    bridge.mint(&user, &signature, &btc_tx_hash, &btc_amount, &btc_amount_str, &nav, &nav_str, &token.address);
}

#[test]
fn test_redeem_success() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    // Set token decimals to 8 
    token.set_token_decimals(&8);

    // Redeem
    let amount = 100_000_000i128; // 1 token
    let receiver = Bytes::from_slice(&env, b"tb1qgj9lq5xse06hgwhv5wrch6g70nmp0jnn22jvr9");
    
    bridge.redeem(&user, &token.address, &amount, &receiver);

    let events = env.events().all();
    let last_event = events.last().unwrap();
    assert_eq!(last_event.1.len(), 3); // topics: redeem, from, token
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")]
fn test_redeem_invalid_amount() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    bridge.redeem(&user, &token.address, &0, &Bytes::new(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #404)")]
fn test_redeem_wrong_token() {
    let (env, bridge, _admin, _token, _oracle, user) = create_test_setup();
    let wrong_token = Address::generate(&env);
    bridge.redeem(&user, &wrong_token, &100, &Bytes::new(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #412)")]
fn test_redeem_invalid_btc_receiver_address() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    let receiver = Bytes::from_slice(&env, b"xQ7Z9p2RfKb3Vd8WsYh4Jn6Mc1EtGg5HjL0SrTiUoXaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ987654321");
    bridge.redeem(&user, &token.address, &100, &receiver);
}

#[test]
fn test_admin_functions() {
    let (env, bridge, _admin, _token, _oracle, _user) = create_test_setup();
    let _rando = Address::generate(&env);

    // Set Oracle Success
    let new_oracle_id = env.register(MockOracle, ());
    bridge.set_oracle(&new_oracle_id);

    // Set Signer Cap
    let (_secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    bridge.set_signer_cap(&signer_key, &500);
}

#[test]
#[should_panic(expected = "Error(Contract, #409)")] // InvalidSignerKey
fn test_set_signer_cap_rejects_invalid_key_format() {
    let (env, bridge, _admin, _token, _oracle, _user) = create_test_setup();

    let mut invalid = [0u8; 65];
    invalid[0] = 0x02; // compressed prefix
    let signer = BytesN::from_array(&env, &invalid);

    bridge.set_signer_cap(&signer, &500);
}

#[test]
#[should_panic(expected = "Error(Contract, #409)")] // InvalidSignerKey
fn test_set_signer_cap_rejects_all_zero_key() {
    let (env, bridge, _admin, _token, _oracle, _user) = create_test_setup();

    let signer = BytesN::from_array(&env, &[0u8; 65]);
    bridge.set_signer_cap(&signer, &500);
}

#[test]
#[should_panic] // Unauthorized (host Auth error or BridgeError::Unauthorized)
fn test_admin_fail_not_owner() {
    let env = Env::default();
    
    let admin = Address::generate(&env);
    let rando = Address::generate(&env); // 攻击者

    let token_id = env.register(MockToken, ());
    let oracle_id = env.register(MockOracle, ());
    let bridge_id = env.register(SolvBTCBridge, (&admin, &token_id, &oracle_id));
    let bridge = SolvBTCBridgeClient::new(&env, &bridge_id);

    env.mock_auths(&[
        MockAuth {
            address: &rando,
            invoke: &MockAuthInvoke {
                contract: &bridge_id,
                fn_name: "set_signer_cap",
                args: (&BytesN::from_array(&env, &[0u8; 65]), &500_i128).into_val(&env),
                sub_invokes: &[],
            },
        },
    ]);

    let signer = BytesN::from_array(&env, &[0u8; 65]);
    
    bridge.set_signer_cap(&signer, &500);
}

#[test]
#[should_panic(expected = "Error(Contract, #411)")]
fn test_validate_decimals_single_too_large_bridge() {
    let env = Env::default();
    // shares_decimals > 18 should be rejected
    SolvBTCBridge::validate_decimals_config(&env, 19, 8, 8);
}

#[test]
#[should_panic(expected = "Error(Contract, #411)")]
fn test_validate_decimals_sum_too_large_bridge() {
    let env = Env::default();
    // 18 + 18 + 10 = 46 > 38 should be rejected
    SolvBTCBridge::validate_decimals_config(&env, 18, 18, 10);
}

#[test]
fn test_validate_decimals_max_valid_bridge() {
    let env = Env::default();
    // 18 + 18 + 2 = 38 is the max valid configuration
    SolvBTCBridge::validate_decimals_config(&env, 18, 18, 2);
}

#[test]
fn test_calculate_mint_no_overflow_safe_decimals_bridge() {
    let env = Env::default();

    // Safe configuration: 8, 8, 8 with NAV = 1.0
    let deposit_amount = 1_000_000_000_000i128;
    let nav = 100_000_000i128; // 1.0 with 8 decimals

    let minted = SolvBTCBridge::calculate_mint_amount(
        &env,
        deposit_amount,
        nav,
        8,  // currency_decimals (BTC)
        8,  // shares_decimals
        8,  // nav_decimals
    );

    assert!(minted > 0);
    assert_eq!(minted, deposit_amount);
}

#[test]
#[should_panic(expected = "Error(Contract, #411)")]
fn test_calculate_mint_invalid_decimals_bridge() {
    let env = Env::default();

    // Invalid configuration: currency_decimals > 18
    SolvBTCBridge::calculate_mint_amount(
        &env,
        1_000i128,
        100i128,
        19,
        18,
        8,
    );
}

#[test]
fn test_calculate_withdraw_no_overflow_safe_decimals_bridge() {
    let env = Env::default();

    // Safe configuration: 8, 8, 8 with NAV = 1.0
    let shares = 1_000_000_000_000i128;
    let nav = 100_000_000i128; // 1.0 with 8 decimals

    let amount = SolvBTCBridge::calculate_withdraw_amount(
        &env,
        shares,
        nav,
        8,  // shares_token_decimals
        8,  // withdraw_token_decimals (BTC)
        8,  // nav_decimals
    );

    assert!(amount > 0);
    assert_eq!(amount, shares);
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")] // InvalidAmount
fn test_calculate_withdraw_overflow_scale_bridge() {
    let env = Env::default();
    // withdraw_decimals (18) > shares_decimals (8). scale = 10^(18-8) = 10^10.
    // shares = i128::MAX. shares * scale overflows.
    SolvBTCBridge::calculate_withdraw_amount(
        &env,
        i128::MAX,
        100_000_000i128, // nav = 1.0 (8 decimals)
        8,               // shares_token_decimals
        18,              // withdraw_token_decimals
        8,               // nav_decimals
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #411)")]
fn test_calculate_withdraw_invalid_decimals_bridge() {
    let env = Env::default();

    // Invalid configuration: withdraw_token_decimals > 18
    SolvBTCBridge::calculate_withdraw_amount(
        &env,
        1_000i128,
        100i128,
        18,
        19,
        8,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")] // InvalidAmount
fn test_op_return_hash_to_hex_string_bytes_too_long_bridge() {
    let env = Env::default();
    let data = Bytes::from_slice(&env, &[0u8; 33]); // MAX_OP_RETURN_HASH_LENGTH is 32
    SolvBTCBridge::op_return_hash_to_hex_string_bytes(&env, &data);
}

#[test]
#[should_panic]
fn test_i128_to_ascii_bytes_panics_on_min_value_bridge() {
    let env = Env::default();
    let user = Address::generate(&env);
    let token = Address::generate(&env);
    let btc_tx_hash = Bytes::from_slice(&env, &[0u8; 64]); // 64-byte hex string
    let btc_amount_str = Bytes::from_slice(&env, b"min");
    let op_return_hash_hex = Bytes::from_slice(&env, b"00");
    let nav_str = Bytes::from_slice(&env, b"1.0");

    // i128_to_ascii_bytes negates negative numbers; i128::MIN overflows when negated.
    SolvBTCBridge::build_mint_message(
        &env,
        &btc_tx_hash,
        &btc_amount_str,
        i128::MIN,
        &op_return_hash_hex,
        &nav_str,
        100_000_000i128,
        &user,
        &token,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #411)")]
fn test_set_oracle_rejects_invalid_decimals_bridge() {
    let (env, bridge, _admin, token, _oracle, _user) = create_test_setup();

    // Ensure shares_decimals is at upper bound
    token.set_token_decimals(&18);

    // New oracle with nav_decimals that make the sum 18 + 8 + 13 = 39 > 38
    let new_oracle_id = env.register(MockOracle, ());
    let new_oracle_client = MockOracleClient::new(&env, &new_oracle_id);
    new_oracle_client.set_decimals_val(&13);

    bridge.set_oracle(&new_oracle_id);
}

#[test]
fn test_get_signer_cap() {
    let (env, bridge, _admin, _token, _oracle, _user) = create_test_setup();
    let (_secret_key, public_key) = generate_keypair();
    let signer_key = get_signer_cap_key(&env, &public_key);
    
    // Initially should be 0
    assert_eq!(bridge.get_signer_cap(&signer_key), 0);
    
    // Set cap
    let cap = 500_000_000i128;
    bridge.set_signer_cap(&signer_key, &cap);
    
    // Check if it updates
    assert_eq!(bridge.get_signer_cap(&signer_key), cap);
}

#[test]
fn test_get_token() {
    let (_env, bridge, _admin, token, _oracle, _user) = create_test_setup();
    assert_eq!(bridge.get_token(), token.address);
}

#[test]
fn test_get_oracle() {
    let (_env, bridge, _admin, _token, oracle, _user) = create_test_setup();
    assert_eq!(bridge.get_oracle(), oracle.address);
}

#[test]
#[should_panic(expected = "Error(Contract, #402)")] // InvalidNav
fn test_calculate_mint_invalid_nav_zero() {
    let env = Env::default();
    SolvBTCBridge::calculate_mint_amount(
        &env,
        1000,
        0, // nav = 0
        8,
        8,
        8
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")] // InvalidAmount
fn test_calculate_mint_overflow_scale() {
    let env = Env::default();
    // shares_decimals (18) > currency_decimals (8). scale = 10^(18-8) = 10^10.
    // deposit = i128::MAX. deposit * scale overflows.
    SolvBTCBridge::calculate_mint_amount(
        &env,
        i128::MAX,
        100_000_000,
        8,
        18,
        8
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")] // InvalidAmount
fn test_calculate_mint_overflow_final_calc() {
    let env = Env::default();
    // shares_decimals (8) == currency_decimals (8). common_factor = 8. scale = 1.
    // scaled_amount = deposit.
    // nav_scale = 10^8.
    // deposit * nav_scale overflows.
    SolvBTCBridge::calculate_mint_amount(
        &env,
        i128::MAX,
        100_000_000, // nav
        8,
        8,
        8
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #406)")] // InvalidSignature
fn test_mint_invalid_signature_recovery_id() {
    let (env, bridge, _admin, token, _oracle, user) = create_test_setup();
    
    // Prepare valid data structure but invalid signature
    let btc_tx_hash = Bytes::from_slice(&env, &[0x55; 64]); // 64-byte hex string
    let btc_amount = 100_000_000i128;
    let btc_amount_str = Bytes::from_slice(&env, b"1.0");
    let nav = 100_000_000i128;
    let nav_str = Bytes::from_slice(&env, b"1.0");

    // Construct a signature with invalid V (recovery ID > 1)
    // Valid V is 27 or 28 (or 0 or 1). 
    // If we use V=30, recovery_id = 30-27 = 3 > 1.
    let mut sig_bytes = [0u8; 65];
    // Fill with some dummy data
    sig_bytes[0] = 1; 
    sig_bytes[64] = 30; // V = 30 triggers panic

    let signature = BytesN::from_array(&env, &sig_bytes);
    
    bridge.mint(
        &user,
        &signature,
        &btc_tx_hash,
        &btc_amount,
        &btc_amount_str,
        &nav,
        &nav_str,
        &token.address
    );
}

#[test]
fn test_calculate_mint_shares_lt_currency_success() {
    let env = Env::default();
    
    let minted = SolvBTCBridge::calculate_mint_amount(
        &env,
        1000,
        100_000_000,
        10,
        8,
        8
    );
    
    assert_eq!(minted, 10);
}

#[test]
#[should_panic(expected = "Error(Contract, #401)")]
fn test_calculate_mint_shares_lt_currency_overflow_final() {
    let env = Env::default();
    // scaled * nav_scale = (MAX/100) * 10^8 = MAX * 10^6 -> Overflow
    SolvBTCBridge::calculate_mint_amount(
        &env,
        i128::MAX,
        100_000_000,
        10,
        8,
        8
    );
}
