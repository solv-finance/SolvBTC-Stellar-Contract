use soroban_sdk::{contractclient, Env, Address};

// Define client interfaces for inter-contract communication
#[contractclient(name = "TokenClient")]
pub trait TokenInterface {
    fn balance_of(env: Env, account: Address) -> i128;
    fn burn(env: Env, amount: i128);
    fn mint(env: Env, to: Address, amount: i128);
    fn decimals(env: Env) -> u32;
    fn transfer(env: Env, from: Address, to: Address, amount: i128);
    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128);
    fn approve(env: Env, from: Address, spender: Address, amount: i128);
}