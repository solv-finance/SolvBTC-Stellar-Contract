import pkg from '@stellar/stellar-sdk';
const { Keypair, hash, nativeToScVal } = pkg;
import { createHash } from 'crypto';

/**
 * 生成提款签名，与vault合约兼容
 * 
 * @param {Object} params - 签名参数
 * @param {string} params.secretKey - 验证者的私钥
 * @param {string} params.userAddress - 用户地址
 * @param {BigInt} params.targetAmount - 目标提款金额
 * @param {string} params.targetToken - 目标代币地址
 * @param {BigInt} params.nav - 当前NAV值
 * @param {number} params.timestamp - 时间戳
 * @param {string} params.domainName - EIP712域名
 * @param {string} params.domainVersion - EIP712域版本
 * @param {string} params.chainId - 链ID
 * @param {string} params.contractAddress - 合约地址
 * @returns {Object} 签名结果，包含签名和请求哈希
 */
export async function generateWithdrawSignature(params) {
  const {
    secretKey,
    userAddress,
    targetAmount,
    targetToken,
    nav,
    timestamp,
    domainName,
    domainVersion,
    chainId,
    contractAddress,
    domainSeparator // 新增参数：直接使用合约提供的域分隔符
  } = params;

  console.log("生成提款签名...");
  console.log("用户地址:", userAddress);
  console.log("目标金额:", targetAmount.toString());
  console.log("目标代币:", targetToken);
  console.log("NAV:", nav.toString());
  console.log("时间戳:", timestamp);
  
  // 创建随机请求哈希
  const requestHash = createRandomBytes(32);
  
  // 1. 创建提款消息
  const withdrawMessage = createWithdrawMessage({
    userAddress,
    targetAmount,
    targetToken,
    nav,
    requestHash,
    timestamp
  });
  
  // 2. 计算消息哈希
  const messageHash = sha256(withdrawMessage);
  
  // 3. 创建EIP712签名消息
  const eip712Message = createEIP712SignatureMessage(domainSeparator, messageHash);
  
  // 4. 使用私钥签名
  const keypair = Keypair.fromSecret(secretKey);
  const signature = keypair.sign(eip712Message);
  
  console.log("签名生成完成");
  
  return {
    signature: signature,
    requestHash: requestHash
  };
}

/**
 * 创建提款消息 - 确保与vault合约中的create_withdraw_message完全一致
 */
function createWithdrawMessage(params) {
  const {
    userAddress,
    targetAmount,
    targetToken,
    nav,
    requestHash,
    timestamp
  } = params;
  
  // 创建一个缓冲区来存储所有字段
  let buffer = Buffer.alloc(0);
  
  // 1. 添加用户地址XDR
  // 使用stellar-sdk的Address转换为XDR格式
  const address = new pkg.Address(userAddress);
  const userAddressXDR = nativeToScVal(address).toXDR();
  buffer = Buffer.concat([buffer, Buffer.from(userAddressXDR)]);
  
  // 2. 添加目标金额 (i128 to_be_bytes)
  const targetAmountBuffer = Buffer.alloc(16); // i128需要16字节
  // JavaScript只支持到64位，这里需要特殊处理
  // 对于正数，高8字节为0
  for (let i = 0; i < 8; i++) {
    targetAmountBuffer[i] = 0;
  }
  // 低8字节写入目标金额
  targetAmountBuffer.writeBigInt64BE(targetAmount, 8);
  buffer = Buffer.concat([buffer, targetAmountBuffer]);
  
  // 3. 添加目标代币XDR
  const targetAddress = new pkg.Address(targetToken);
  const targetTokenXDR = nativeToScVal(targetAddress).toXDR();
  buffer = Buffer.concat([buffer, Buffer.from(targetTokenXDR)]);
  
  // 4. 添加用户哈希 (与合约中一致)
  const userHash = sha256(Buffer.from(requestHash, 'hex'));
  buffer = Buffer.concat([buffer, userHash]);
  
  // 5. 添加NAV值 (i128 to_be_bytes)
  const navBuffer = Buffer.alloc(16); // i128需要16字节
  // 高8字节为0
  for (let i = 0; i < 8; i++) {
    navBuffer[i] = 0;
  }
  // 低8字节写入NAV值
  navBuffer.writeBigInt64BE(nav, 8);
  buffer = Buffer.concat([buffer, navBuffer]);
  
  // 6. 添加请求哈希
  buffer = Buffer.concat([buffer, Buffer.from(requestHash, 'hex')]);
  
  // 7. 添加时间戳 (u64 to_be_bytes)
  const timestampBuffer = Buffer.alloc(8);
  timestampBuffer.writeBigUInt64BE(BigInt(timestamp));
  buffer = Buffer.concat([buffer, timestampBuffer]);
  return buffer;
}

/**
 * 计算EIP712域分隔符
 */
function calculateDomainSeparator(params) {
  const {
    domainName,
    domainVersion,
    chainId,
    contractAddress
  } = params;
  
  // 创建一个缓冲区来存储所有字段
  let buffer = Buffer.alloc(0);
  
  // 1. EIP712Domain的TypeHash
  const typeHash = sha256(Buffer.from("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"));
  buffer = Buffer.concat([buffer, typeHash]);
  
  // 2. 域名哈希
  const nameHash = sha256(Buffer.from(domainName));
  buffer = Buffer.concat([buffer, nameHash]);
  
  // 3. 版本哈希
  const versionHash = sha256(Buffer.from(domainVersion));
  buffer = Buffer.concat([buffer, versionHash]);
  
  // 4. 链ID
  buffer = Buffer.concat([buffer, Buffer.from(chainId, 'hex')]);
  
  // 5. 合约地址哈希
  const contractHash = sha256(Buffer.from(contractAddress));
  buffer = Buffer.concat([buffer, contractHash]);
  
  // 6. 盐值（32字节的零值）
  const salt = Buffer.alloc(32);
  buffer = Buffer.concat([buffer, salt]);
  
  // 返回域分隔符哈希
  return sha256(buffer);
}

/**
 * 创建EIP712签名消息
 */
function createEIP712SignatureMessage(domainSeparator, messageHash) {
  // 创建一个缓冲区来存储所有字段
  let buffer = Buffer.alloc(0);
  
  // 1. 添加EIP712固定前缀 \x19\x01
  buffer = Buffer.concat([buffer, Buffer.from([0x19, 0x01])]);
  
  // 2. 添加域分隔符
  buffer = Buffer.concat([buffer, domainSeparator]);
  
  // 3. 添加消息哈希
  buffer = Buffer.concat([buffer, messageHash]);
  
  return buffer;
}

/**
 * SHA-256哈希函数
 */
function sha256(data) {
  return createHash('sha256').update(data).digest();
}

/**
 * 生成随机字节
 */
function createRandomBytes(length) {
  const buffer = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    buffer[i] = Math.floor(Math.random() * 256);
  }
  return buffer;
}

/**
 * 获取域分隔符
 */
export async function getDomainSeparator(vaultClient) {
  try {
    const domainSeparatorOp = await vaultClient.get_eip712_domain_separator();
    const domainSeparatorResult = await domainSeparatorOp.simulate();
    return domainSeparatorResult.result;
  } catch (error) {
    console.error("获取域分隔符出错:", error.message);
    return null;
  }
}

/**
 * 获取域名
 */
export async function getDomainName(vaultClient) {
  try {
    const domainNameOp = await vaultClient.get_eip712_domain_name();
    const domainNameResult = await domainNameOp.simulate();
    return domainNameResult.result;
  } catch (error) {
    console.error("获取域名出错:", error.message);
    return "SolvBTC Vault"; // 默认值
  }
}

/**
 * 获取域版本
 */
export async function getDomainVersion(vaultClient) {
  try {
    const domainVersionOp = await vaultClient.get_eip712_domain_version();
    const domainVersionResult = await domainVersionOp.simulate();
    const versionStr = domainVersionResult.result;
    
    // 处理"{string:1}"格式的版本号
    if (typeof versionStr === 'string' && versionStr.startsWith('{string:')) {
      return versionStr.substring(8, versionStr.length - 1);
    }
    
    return versionStr;
  } catch (error) {
    console.error("获取域版本出错:", error.message);
    return "1"; // 默认值
  }
}

/**
 * 获取链ID
 */
export async function getChainId(vaultClient) {
  try {
    const chainIdOp = await vaultClient.get_eip712_chain_id();
    const chainIdResult = await chainIdOp.simulate();
    return chainIdResult.result;
  } catch (error) {
    console.error("获取链ID出错:", error.message);
    return Buffer.alloc(32).toString('hex'); // 默认值
  }
} 