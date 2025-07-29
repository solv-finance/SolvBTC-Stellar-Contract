// vault 合约存款功能测试
use soroban_sdk::{Address, symbol_short, String};
use super::{create_vault_test_env, VaultTestSetup};

#[cfg(test)]
mod vault_deposit_tests {
    use super::*;

    #[test]
    fn test_deposit_btc_success() {
        // 1. 设置测试环境
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        // 2. 准备测试数据
        let deposit_amount = 1_0000000; // 0.1 BTC (7 decimals)
        let currency = setup.mint_test_currency(&setup.user, deposit_amount * 2);

        // 3. 记录存款前状态
        let vault_balance_before = setup.vault_client.get_currency_balance(&env, &currency);
        let user_solvbtc_balance_before = setup.token_client.balance(&env, &setup.user);

        // 4. 执行存款操作
        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &currency,
            &deposit_amount,
        );

        // 5. 验证操作成功
        assert!(result.is_ok());

        // 6. 验证余额更新
        let vault_balance_after = setup.vault_client.get_currency_balance(&env, &currency);
        let user_solvbtc_balance_after = setup.token_client.balance(&env, &setup.user);

        assert_eq!(vault_balance_after, vault_balance_before + deposit_amount);
        assert_eq!(user_solvbtc_balance_after, user_solvbtc_balance_before + deposit_amount);

        // 7. 验证事件发出
        let events = env.events().all();
        let deposit_event = events.iter().find(|event| {
            event.topics.contains(&symbol_short!("deposit"))
        });
        assert!(deposit_event.is_some());
    }

    #[test]
    fn test_deposit_with_zero_amount_fails() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        let currency = setup.mint_test_currency(&setup.user, 1000);

        // 尝试存入零金额
        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &currency,
            &0,
        );

        // 验证操作失败
        assert!(result.is_err());
        
        // 验证错误类型
        match result {
            Err(solvbtc_vault::ContractError::InvalidAmount) => {
                // 预期的错误
            },
            _ => panic!("Expected InvalidAmount error"),
        }
    }

    #[test]
    fn test_deposit_unsupported_currency_fails() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        // 使用未支持的货币
        let unsupported_currency = Address::generate(&env);
        let deposit_amount = 1_0000000;

        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &unsupported_currency,
            &deposit_amount,
        );

        assert!(result.is_err());
        match result {
            Err(solvbtc_vault::ContractError::UnsupportedCurrency) => {
                // 预期的错误
            },
            _ => panic!("Expected UnsupportedCurrency error"),
        }
    }

    #[test]
    fn test_deposit_with_paused_contract_fails() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        let currency = setup.mint_test_currency(&setup.user, 1000);

        // 暂停合约
        setup.vault_client.pause(&env, &setup.admin);

        // 尝试存款
        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &currency,
            &1_0000000,
        );

        assert!(result.is_err());
        match result {
            Err(solvbtc_vault::ContractError::ContractPaused) => {
                // 预期的错误
            },
            _ => panic!("Expected ContractPaused error"),
        }
    }

    #[test]
    fn test_deposit_events_emitted() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        let deposit_amount = 5_0000000; // 0.5 BTC
        let currency = setup.mint_test_currency(&setup.user, deposit_amount);

        // 执行存款
        setup.vault_client.deposit(&env, &setup.user, &currency, &deposit_amount);

        // 检查事件
        let events = env.events().all();
        
        // 查找存款事件
        let deposit_event = events.iter().find(|event| {
            event.topics.contains(&symbol_short!("deposit")) &&
            event.topics.contains(&setup.user) &&
            event.topics.contains(&currency)
        });
        
        assert!(deposit_event.is_some());
        
        if let Some(event) = deposit_event {
            // 验证事件数据
            let event_data: (Address, Address, i128) = event.data.get(&env).unwrap();
            assert_eq!(event_data.0, setup.user);
            assert_eq!(event_data.1, currency);
            assert_eq!(event_data.2, deposit_amount);
        }
    }

    #[test]
    fn test_deposit_with_minimum_amount() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        // 测试最小存款金额
        let min_amount = 1; // 最小单位
        let currency = setup.mint_test_currency(&setup.user, min_amount);

        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &currency,
            &min_amount,
        );

        // 根据合约逻辑，可能有最小存款限制
        // 这里需要根据实际业务逻辑调整
        if setup.vault_client.get_min_deposit_amount(&env, &currency) <= min_amount {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_deposit_with_maximum_amount() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        let max_amount = i128::MAX / 2; // 避免溢出
        let currency = setup.mint_test_currency(&setup.user, max_amount);

        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &currency,
            &max_amount,
        );

        // 验证大额存款处理
        // 可能会有最大存款限制或其他检查
        match result {
            Ok(_) => {
                // 验证余额正确更新
                let balance = setup.token_client.balance(&env, &setup.user);
                assert_eq!(balance, max_amount);
            },
            Err(e) => {
                // 如果有最大限制，验证错误类型
                println!("Large deposit failed as expected: {:?}", e);
            }
        }
    }

    #[test]
    fn test_multiple_deposits_accumulate() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        let currency = setup.mint_test_currency(&setup.user, 10_0000000);
        
        // 执行多次存款
        let amounts = vec![1_0000000, 2_0000000, 3_0000000]; // 0.1, 0.2, 0.3 BTC
        let mut expected_total = 0;

        for amount in amounts {
            setup.vault_client.deposit(&env, &setup.user, &currency, &amount);
            expected_total += amount;
            
            // 验证累积余额
            let current_balance = setup.token_client.balance(&env, &setup.user);
            assert_eq!(current_balance, expected_total);
        }
    }

    #[test]
    fn test_deposit_with_price_update() {
        let (env, setup) = create_vault_test_env();
        setup.initialize_contracts();

        let currency = setup.mint_test_currency(&setup.user, 10_0000000);
        
        // 更新 BTC 价格
        let new_price = 60000_0000000; // $60,000
        setup.oracle_client.update_price(
            &env,
            &setup.admin,
            &symbol_short!("BTC"),
            &new_price,
        );

        // 执行存款
        let deposit_amount = 1_0000000;
        let result = setup.vault_client.try_deposit(
            &env,
            &setup.user,
            &currency,
            &deposit_amount,
        );

        assert!(result.is_ok());
        
        // 验证存款仍然按 1:1 比例铸造代币
        // （价格更新主要影响取款计算）
        let balance = setup.token_client.balance(&env, &setup.user);
        assert_eq!(balance, deposit_amount);
    }
} 