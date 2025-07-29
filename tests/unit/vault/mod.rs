// vault 合约单元测试模块
use soroban_sdk::{Env, Address, symbol_short};
use crate::test_utils::{create_test_env, setup_contracts, TestConfig};

mod initialization_tests;
mod deposit_tests;
mod withdrawal_tests;
mod liquid_staking_tests;

pub use initialization_tests::*;
pub use deposit_tests::*;
pub use withdrawal_tests::*;
pub use liquid_staking_tests::*;

/// 创建测试用的 Vault 环境
pub fn create_vault_test_env() -> (Env, VaultTestSetup) {
    let env = create_test_env();
    let contracts = setup_contracts(&env);
    
    let setup = VaultTestSetup {
        env: env.clone(),
        vault_client: contracts.vault_client,
        token_client: contracts.token_client,
        oracle_client: contracts.oracle_client,
        minter_manager_client: contracts.minter_manager_client,
        admin: contracts.admin,
        user: contracts.user,
        treasurer: contracts.treasurer,
        config: TestConfig::default(),
    };
    
    (env, setup)
}

pub struct VaultTestSetup {
    pub env: Env,
    pub vault_client: VaultClient,
    pub token_client: TokenClient,
    pub oracle_client: OracleClient,
    pub minter_manager_client: MinterManagerClient,
    pub admin: Address,
    pub user: Address,
    pub treasurer: Address,
    pub config: TestConfig,
}

impl VaultTestSetup {
    /// 初始化所有合约为可用状态
    pub fn initialize_contracts(&self) {
        // 初始化 Oracle
        self.oracle_client.initialize(
            &self.env,
            &self.admin,
            &symbol_short!("BTC"),
            &self.config.initial_btc_price,
        );
        
        // 初始化 Token
        self.token_client.initialize(
            &self.env,
            &self.admin,
            &symbol_short!("solvBTC"),
            &symbol_short!("sBTC"),
            18,
        );
        
        // 初始化 MinterManager
        self.minter_manager_client.initialize(
            &self.env,
            &self.admin,
        );
        
        // 将 Vault 添加为铸币者
        self.minter_manager_client.add_minter(
            &self.env,
            &self.admin,
            &self.vault_client.address,
        );
        
        // 初始化 Vault
        let vault_config = solvbtc_vault::InitializeConfig {
            admin: self.admin.clone(),
            minter_manager: self.minter_manager_client.address.clone(),
            token_contract: self.token_client.address.clone(),
            oracle: self.oracle_client.address.clone(),
            treasurer: self.treasurer.clone(),
            withdraw_verifier: self.admin.clone(),
            withdraw_fee_ratio: self.config.withdrawal_fee_ratio,
            withdraw_fee_receiver: self.admin.clone(),
            eip712_domain_name: String::from_str(&self.env, "SolvBTC-Test"),
            eip712_domain_version: String::from_str(&self.env, "1"),
        };
        
        self.vault_client.initialize_with_config(&self.env, &vault_config);
    }
    
    /// 为用户铸造测试代币
    pub fn mint_test_currency(&self, to: &Address, amount: i128) -> Address {
        let currency = Address::generate(&self.env);
        
        // 添加支持的货币
        self.vault_client.add_supported_currency(
            &self.env,
            &self.admin,
            &currency,
        );
        
        // 模拟铸造货币代币给用户
        // 这里应该使用实际的货币合约来铸造
        
        currency
    }
} 