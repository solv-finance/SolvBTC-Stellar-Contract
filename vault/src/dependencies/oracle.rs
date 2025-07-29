use soroban_sdk::{contractclient, Env};

// Define client interfaces for inter-contract communication
#[contractclient(name = "OracleClient")]
pub trait OracleInterface {
    fn get_nav(env: Env) -> i128;
    fn get_nav_decimals(env: Env) -> u32;
}