use soroban_sdk::{contractclient, Env};


#[contractclient(name = "VaultClient")]
pub trait VaultInterface {
    fn get_withdraw_fee_ratio(env: Env) -> i128;
}