use soroban_sdk::{contractclient, Env, Address};

// Define client interfaces for inter-contract communication
#[contractclient(name = "MinterManagerClient")]
pub trait MinterManagerInterface {
    fn burn(env: Env, from: Address, amount: i128);
    fn mint(env: Env, from: Address, to: Address, amount: i128);
    fn is_minter(env: Env, minter: Address) -> bool;
}