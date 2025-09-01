#![allow(dead_code)]
use soroban_sdk::{contractclient, Address, Env};

// Define client interfaces for inter-contract communication
#[contractclient(name = "TokenClient")]
pub trait TokenInterface {
    fn balance(env: Env, account: Address) -> i128;
    fn decimals(env: Env) -> u32;
    fn approve(env: Env, owner: Address, spender: Address, amount: i128, live_until_ledger: u32);
    fn transfer(env: Env, from: Address, to: Address, amount: i128);
    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128);
    fn burn(env: Env, from: Address, amount: i128);
    fn burn_from(env: Env, spender: Address, from: Address, amount: i128);
    fn mint_from(env: Env, from: Address, to: Address, amount: i128);
}
