#![cfg(test)]
extern crate std;
use super::*;
use soroban_sdk::{
    testutils::Address as _,
    testutils::{MockAuth, MockAuthInvoke},
    Address, Env, IntoVal,
};
use std::println;

// 创建合约和客户端的辅助函数
fn create_oracle_contract(env: &Env) -> (SolvBtcOracleClient, Address) {
    let contract_address = env.register(SolvBtcOracle, ());
    let client = SolvBtcOracleClient::new(env, &contract_address);
    (client, contract_address)
}

// ==================== 初始化测试 ====================

#[test]
fn test_initialize_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 成功初始化
    client.initialize(&admin, &8, &1000000000, &500); // 8位小数，初始NAV=10，最大变化5%

    // 验证初始化状态
    assert!(client.is_initialized());
    assert_eq!(client.admin(), admin);
    assert_eq!(client.get_nav(), 1000000000);
    assert_eq!(client.get_nav_decimals(), 8);
    assert_eq!(client.max_nav_change_percent(), 500);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_nav_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 尝试使用超过最大值的小数位数
    client.initialize(&admin, &19, &1000000000, &500);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_initial_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 尝试使用负数NAV
    client.initialize(&admin, &8, &-1000000000, &500);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_initialize_invalid_max_change_percent() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 尝试使用超过100%的最大变化百分比
    client.initialize(&admin, &8, &1000000000, &10001);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_initialize_already_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 第一次初始化
    client.initialize(&admin, &8, &1000000000, &500);

    // 第二次初始化应该失败
    client.initialize(&admin, &8, &2000000000, &1000);
}

// ==================== NAV查询测试 ====================

#[test]
#[should_panic(expected = "HostError: Error(Contract, #3)")]
fn test_nav_queries_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _) = create_oracle_contract(&env);

    // 未初始化时查询应该失败
    client.get_nav();
}

// ==================== 管理员功能测试 ====================

#[test]
fn test_set_nav_manager_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约
    client.initialize(&admin, &8, &1000000000, &500);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 验证设置成功
    assert_eq!(client.nav_manager(), Some(nav_manager));
}

#[test]
fn test_set_max_nav_change_by_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约
    client.initialize(&admin, &8, &1000000000, &500);

    // 修改最大变化百分比
    client.set_max_nav_change_by_admin(&1000);

    // 验证修改成功
    assert_eq!(client.max_nav_change_percent(), 1000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_set_max_nav_change_invalid() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约
    client.initialize(&admin, &8, &1000000000, &500);

    // 尝试设置无效的最大变化百分比
    client.set_max_nav_change_by_admin(&10001);
}

// ==================== NAV管理员功能测试 ====================

#[test]
fn test_set_nav_by_manager_success() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约
    client.initialize(&admin, &8, &1000000000, &500);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // NAV管理员设置新的NAV值（变化4%，在允许范围内）
    client.set_nav_by_manager(&1040000000);

    // 验证设置成功
    assert_eq!(client.get_nav(), 1040000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_set_nav_by_manager_exceeds_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约（最大变化5%）
    client.initialize(&admin, &8, &1000000000, &500);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 尝试设置变化超过5%的NAV值（变化6%）
    client.set_nav_by_manager(&1060000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #6)")]
fn test_set_nav_by_manager_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约但不设置NAV管理员
    client.initialize(&admin, &8, &1000000000, &500);

    // 尝试设置NAV（应该失败，因为没有设置NAV管理员）
    client.set_nav_by_manager(&1040000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_set_nav_by_manager_invalid_nav() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约
    client.initialize(&admin, &8, &1000000000, &500);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 尝试设置负数NAV
    client.set_nav_by_manager(&-1000000000);
}

// ==================== 边界条件测试 ====================

#[test]
fn test_zero_max_change_percent() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约（最大变化0%）
    client.initialize(&admin, &8, &1000000000, &0);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 设置相同的NAV值应该成功
    client.set_nav_by_manager(&1000000000);

    assert_eq!(client.get_nav(), 1000000000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_zero_max_change_percent_with_change() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约（最大变化0%）
    client.initialize(&admin, &8, &1000000000, &0);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 任何变化都应该失败
    client.set_nav_by_manager(&1000000001);
}

#[test]
fn test_maximum_nav_change() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约（最大变化100%）
    client.initialize(&admin, &8, &1000000000, &10000);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 100%的变化应该成功
    client.set_nav_by_manager(&2000000000);
    assert_eq!(client.get_nav(), 2000000000);

    // 向下100%的变化也应该成功（从20到10）
    client.set_nav_by_manager(&1000000000);
    assert_eq!(client.get_nav(), 1000000000);
}

// ==================== 精度测试 ====================

#[test]
fn test_nav_change_precision() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约（最大变化0.01%）
    client.initialize(&admin, &8, &1000000000, &1);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 0.01%的变化应该成功
    client.set_nav_by_manager(&1000100000);
    assert_eq!(client.get_nav(), 1000100000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_nav_change_precision_exceeds() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 初始化合约（最大变化0.01%）
    client.initialize(&admin, &8, &1000000000, &1);

    // 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 0.02%的变化应该失败
    client.set_nav_by_manager(&1000200000);
}

// ==================== 边界值测试 ====================

#[test]
fn test_minimum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 0位小数应该成功
    client.initialize(&admin, &0, &10, &500);

    assert_eq!(client.get_nav_decimals(), 0);
}

#[test]
fn test_maximum_decimals() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 18位小数应该成功
    client.initialize(&admin, &18, &1000000000000000000, &500);

    assert_eq!(client.get_nav_decimals(), 18);
}

// ==================== 综合测试 ====================

#[test]
fn test_complete_workflow() {
    let env = Env::default();
    env.mock_all_auths(); // 使用简单的全局授权模拟

    let admin = Address::generate(&env);
    let nav_manager = Address::generate(&env);
    let (client, _) = create_oracle_contract(&env);

    // 1. 初始化合约
    client.initialize(&admin, &8, &1000000000, &500);

    // 2. 设置NAV管理员
    client.set_nav_manager_by_admin(&nav_manager);

    // 3. 更新NAV值
    client.set_nav_by_manager(&1050000000);
    assert_eq!(client.get_nav(), 1050000000);

    // 4. 修改最大变化百分比
    client.set_max_nav_change_by_admin(&1000);
    assert_eq!(client.max_nav_change_percent(), 1000);

    // 5. 使用新的限制更新NAV（10%变化）
    client.set_nav_by_manager(&1155000000);
    assert_eq!(client.get_nav(), 1155000000);

    // 6. 验证所有状态
    assert!(client.is_initialized());
    assert_eq!(client.admin(), admin);
    assert_eq!(client.nav_manager(), Some(nav_manager));
    assert_eq!(client.get_nav_decimals(), 8);
}

// ==================== 基础测试 ====================

#[test]
fn test_constants() {
    // 测试常量定义是否正确
    assert_eq!(PERCENTAGE_PRECISION, 10000);
    assert_eq!(MAX_NAV_DECIMALS, 18);
}

#[test]
fn test_error_enum() {
    // 测试错误枚举定义
    assert_eq!(OracleError::Unauthorized as u32, 1);
    assert_eq!(OracleError::InvalidArgument as u32, 2);
    assert_eq!(OracleError::NotInitialized as u32, 3);
    assert_eq!(OracleError::AlreadyInitialized as u32, 4);
    assert_eq!(OracleError::NavChangeExceedsLimit as u32, 5);
    assert_eq!(OracleError::NavManagerNotSet as u32, 6);
}
