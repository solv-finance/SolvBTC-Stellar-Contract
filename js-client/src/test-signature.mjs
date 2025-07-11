import pkg from '@stellar/stellar-sdk';
const { Keypair } = pkg;
import { CONFIG } from './config.js';

// 导入合约绑定
import * as vaultModule from '../../js-bindings/vault/dist/index.js';
import * as oracleModule from '../../js-bindings/oracle/dist/index.js';

// 导入签名工具
import { generateWithdrawSignature, getDomainSeparator, getDomainName, getDomainVersion, getChainId } from './signature-utils.mjs';

/**
 * 测试提款签名生成
 */
async function testWithdrawSignature() {
  try {
    console.log("测试提款签名生成...");
    
    // 检查是否有管理员密钥
    if (!CONFIG.accounts.admin || !CONFIG.accounts.admin.secretKey) {
      console.error("请在配置中提供管理员密钥");
      return;
    }
    
    const secretKey = CONFIG.accounts.admin.secretKey;
    const keypair = Keypair.fromSecret(secretKey);
    console.log("用户地址:", keypair.publicKey());
    
    // 创建vault合约客户端
    const vaultClient = new vaultModule.Client({
      contractId: CONFIG.contracts.vault,
      networkPassphrase: CONFIG.network.networkPassphrase,
      rpcUrl: CONFIG.network.rpcUrl,
      allowHttp: true
    });
    
    // 创建oracle合约客户端
    const oracleClient = new oracleModule.Client({
      contractId: CONFIG.contracts.oracle,
      networkPassphrase: CONFIG.network.networkPassphrase,
      rpcUrl: CONFIG.network.rpcUrl,
      allowHttp: true
    });
    
    // 获取当前NAV
    const navResult = await oracleClient.get_nav();
    const nav = navResult.result;
    console.log("当前NAV:", nav);
    
    // 获取提款货币
    const withdrawCurrencyOp = await vaultClient.get_withdraw_currency();
    const withdrawCurrencyResult = await withdrawCurrencyOp.simulate();
    const targetToken = withdrawCurrencyResult.result;
    console.log("提款货币:", targetToken);
    
    // 获取域名、版本和链ID
    const domainNameOp = await vaultClient.get_eip712_domain_name();
    const domainNameResult = await domainNameOp.simulate();
    const domainName = domainNameResult.result;
    console.log("域名:", domainName);
    
    const domainVersionOp = await vaultClient.get_eip712_domain_version();
    const domainVersionResult = await domainVersionOp.simulate();
    let domainVersion = domainVersionResult.result;
    // 处理"{string:1}"格式的版本号
    if (typeof domainVersion === 'string' && domainVersion.startsWith('{string:')) {
      domainVersion = domainVersion.substring(8, domainVersion.length - 1);
    }
    console.log("域版本:", domainVersion);
    
    const chainIdOp = await vaultClient.get_eip712_chain_id();
    const chainIdResult = await chainIdOp.simulate();
    const chainId = chainIdResult.result;
    
    // 获取域分隔符
    const domainSeparatorOp = await vaultClient.get_eip712_domain_separator();
    const domainSeparatorResult = await domainSeparatorOp.simulate();
    const domainSeparator = domainSeparatorResult.result;
    
    // 获取当前时间戳
    const timestamp = Math.floor(Date.now() / 1000);
    
    // 生成真实签名
    const signatureData = await generateWithdrawSignature({
      secretKey,
      userAddress: keypair.publicKey(),
      targetAmount: BigInt(25000000), // 0.25 SBTC
      targetToken,
      nav,
      timestamp,
      domainName,
      domainVersion,
      chainId,
      contractAddress: CONFIG.contracts.vault,
      domainSeparator // 传递域分隔符
    });
    
    console.log("签名数据:", {
      requestHash: Buffer.from(signatureData.requestHash).toString('hex'),
      signature: Buffer.from(signatureData.signature).toString('hex')
    });
    
    // 验证者地址
    const verifierOp = await vaultClient.get_withdraw_verifier();
    const verifierResult = await verifierOp.simulate();
    const verifier = verifierResult.result;
    console.log("验证者地址:", verifier);
    
    console.log("域分隔符:", domainSeparator);
    
    return {
      userAddress: keypair.publicKey(),
      targetAmount: BigInt(25000000),
      targetToken,
      nav,
      timestamp,
      requestHash: signatureData.requestHash,
      signature: signatureData.signature,
      verifier,
      domainSeparator
    };
  } catch (error) {
    console.error("测试签名生成出错:", error.message);
    return null;
  }
}

// 运行测试
testWithdrawSignature()
  .then(result => {
    if (result) {
      console.log("\n===== 测试结果摘要 =====");
      console.log("用户地址:", result.userAddress);
      console.log("目标金额:", result.targetAmount);
      console.log("目标代币:", result.targetToken);
      console.log("NAV:", result.nav.toString());
      console.log("时间戳:", result.timestamp);
      console.log("请求哈希:", Buffer.from(result.requestHash).toString('hex'));
      console.log("签名:", Buffer.from(result.signature).toString('hex'));
      console.log("验证者:", result.verifier);
      console.log("域分隔符:", result.domainSeparator);
    }
  })
  .catch(error => console.error("运行出错:", error)); 