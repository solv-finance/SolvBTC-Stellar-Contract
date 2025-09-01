import pkg from '@stellar/stellar-sdk';
const { Keypair, hash, nativeToScVal } = pkg;
import { createHash } from 'crypto';
import * as bip39 from 'bip39';
import { derivePath } from 'ed25519-hd-key';
import { CONFIG } from './config.js';

/**
 * Generate withdrawal signature, compatible with vault contract
 * 
 * @param {Object} params - Signature parameters
 * @param {string} params.secretKey - Validator's private key
 * @param {string} params.userAddress - User address
 * @param {BigInt} params.targetAmount - Target withdrawal amount
 * @param {string} params.targetToken - Target token address
 * @param {BigInt} params.nav - Current NAV value
 * @param {number} params.timestamp - Timestamp
 * @param {string} params.domainName - EIP712 domain name
 * @param {string} params.domainVersion - EIP712 domain version
 * @param {string} params.chainId - Chain ID
 * @param {string} params.contractAddress - Contract address
 * @returns {Object} Signature result, including signature and request hash
 */
export async function generateWithdrawSignature(params) {
  const {
    secretKey,
    userAddress,
    targetAmount,
    targetToken,
    nav,
    timestamp,
    domainSeparator, // New parameter: directly use the domain separator provided by the contract
    requestHash      // Use the requestHash from withdraw_request step
  } = params;

  console.log("Generating withdraw signature...");
  console.log("User address:", userAddress);
  console.log("Target amount:", targetAmount.toString());
  console.log("Target token:", targetToken);
  console.log("NAV:", nav.toString());
  console.log("Timestamp:", timestamp);
  console.log("Using requestHash from withdraw_request:", Buffer.from(requestHash).toString('hex'));
  
  // Use the provided requestHash instead of generating a new one
  
  // Create withdraw message
  const withdrawMessage = createWithdrawMessage({
    userAddress,
    targetAmount,
    targetToken,
    nav,
    requestHash,
    timestamp
  });
  
  // Calculate message hash
  const messageHash = sha256(withdrawMessage);
  
  // Create EIP712 signature message
  const eip712Message = createEIP712SignatureMessage(domainSeparator, messageHash);
  
  // Choose signing method: either use provided secretKey or derive from mnemonic
  let keypair;

  // Derive key from mnemonic (BIP44 method)
  console.log('Using mnemonic derivation method...');
  const mnemonic = CONFIG.signature?.mnemonic;
  const derivationPath = CONFIG.signature?.derivationPath || "m/44'/148'/0'";
  const password = "";
  
  // Generate seed from mnemonic
  const seedBuffer = await bip39.mnemonicToSeed(mnemonic, password);
  const seedHex = seedBuffer.toString('hex');
  
  // Use BIP44 path to derive key
  console.log(`Using derivation path: ${derivationPath}`);
  const { key } = derivePath(derivationPath, seedHex);
  keypair = Keypair.fromRawEd25519Seed(key);
  console.log('Derived public key:', keypair.publicKey());
  const signature = keypair.sign(eip712Message);
  
  console.log("Signature generated successfully");
  
  return {
    signature: signature,
    requestHash: requestHash
  };
}

/**
 * Create withdrawal message - ensure complete consistency with create_withdraw_message in vault contract
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
  
  // Create a buffer to store all fields
  let buffer = Buffer.alloc(0);
  
  // 1. Add user address XDR
  // Use stellar-sdk's Address to convert to XDR format
  const address = new pkg.Address(userAddress);
  const userAddressXDR = nativeToScVal(address).toXDR();
  buffer = Buffer.concat([buffer, Buffer.from(userAddressXDR)]);
  
  // 2. Add target amount (i128 to_be_bytes)
  const targetAmountBuffer = Buffer.alloc(16); // i128 needs 16 bytes
  // JavaScript only supports up to 64 bits, so we need special handling
  // For positive numbers, the high 8 bytes are 0
  for (let i = 0; i < 8; i++) {
    targetAmountBuffer[i] = 0;
  }
  // Write target amount to the low 8 bytes
  targetAmountBuffer.writeBigInt64BE(targetAmount, 8);
  buffer = Buffer.concat([buffer, targetAmountBuffer]);
  
  // 3. Add target token XDR
  const targetAddress = new pkg.Address(targetToken);
  const targetTokenXDR = nativeToScVal(targetAddress).toXDR();
  buffer = Buffer.concat([buffer, Buffer.from(targetTokenXDR)]);
  
  // 4. Add user hash (same as in contract)
  const userHash = sha256(requestHash);  // requestHash is already a Buffer
  buffer = Buffer.concat([buffer, userHash]);
  
  // 5. Add NAV value (i128 to_be_bytes)
  const navBuffer = Buffer.alloc(16); // i128 needs 16 bytes
  // The high 8 bytes are 0
  for (let i = 0; i < 8; i++) {
    navBuffer[i] = 0;
  }
  // Write NAV value to the low 8 bytes
  navBuffer.writeBigInt64BE(nav, 8);
  buffer = Buffer.concat([buffer, navBuffer]);
  
  // 6. Add request hash
  buffer = Buffer.concat([buffer, requestHash]);  // requestHash is already a Buffer
  
  // 7. Add timestamp (u64 to_be_bytes)
  const timestampBuffer = Buffer.alloc(8);
  timestampBuffer.writeBigUInt64BE(BigInt(timestamp));
  buffer = Buffer.concat([buffer, timestampBuffer]);
  return buffer;
}

/**
 * Calculate EIP712 domain separator
 */
function calculateDomainSeparator(params) {
  const {
    domainName,
    domainVersion,
    chainId,
    contractAddress
  } = params;
  
  // Create a buffer to store all fields
  let buffer = Buffer.alloc(0);
  
  // 1. EIP712Domain's TypeHash
  const typeHash = sha256(Buffer.from("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"));
  buffer = Buffer.concat([buffer, typeHash]);
  
  // 2. Domain name hash
  const nameHash = sha256(Buffer.from(domainName));
  buffer = Buffer.concat([buffer, nameHash]);
  
  // 3. Version hash
  const versionHash = sha256(Buffer.from(domainVersion));
  buffer = Buffer.concat([buffer, versionHash]);
  
  // 4. Chain ID
  buffer = Buffer.concat([buffer, Buffer.from(chainId, 'hex')]);
  
  // 5. Contract address hash
  const contractHash = sha256(Buffer.from(contractAddress));
  buffer = Buffer.concat([buffer, contractHash]);
  
  // 6. Salt (32 bytes of zeros)
  const salt = Buffer.alloc(32);
  buffer = Buffer.concat([buffer, salt]);
  
  // Return domain separator hash
  return sha256(buffer);
}

/**
 * Create EIP712 signature message
 */
function createEIP712SignatureMessage(domainSeparator, messageHash) {
  // Create a buffer to store all fields
  let buffer = Buffer.alloc(0);
  
  // 1. Add EIP712 fixed prefix \x19\x01
  buffer = Buffer.concat([buffer, Buffer.from([0x19, 0x01])]);
  
  // 2. Add domain separator
  buffer = Buffer.concat([buffer, domainSeparator]);
  
  // 3. Add message hash
  buffer = Buffer.concat([buffer, messageHash]);
  
  return buffer;
}

/**
 * SHA-256 hash function
 */
function sha256(data) {
  return createHash('sha256').update(data).digest();
}

/**
 * Generate random bytes
 */
function createRandomBytes(length) {
  const buffer = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    buffer[i] = Math.floor(Math.random() * 256);
  }
  return buffer;
}

/**
 * Get domain separator
 */
export async function getDomainSeparator(vaultClient) {
  try {
    const domainSeparatorOp = await vaultClient.get_eip712_domain_separator();
    const domainSeparatorResult = await domainSeparatorOp.simulate();
    return domainSeparatorResult.result;
  } catch (error) {
    console.error("Error getting domain separator:", error.message);
    return null;
  }
}

/**
 * Get domain name
 */
export async function getDomainName(vaultClient) {
  try {
    const domainNameOp = await vaultClient.get_eip712_domain_name();
    const domainNameResult = await domainNameOp.simulate();
    return domainNameResult.result;
  } catch (error) {
    console.error("Error getting domain name:", error.message);
    return "SolvBTC Vault"; // Default value
  }
}

/**
 * Get domain version
 */
export async function getDomainVersion(vaultClient) {
  try {
    const domainVersionOp = await vaultClient.get_eip712_domain_version();
    const domainVersionResult = await domainVersionOp.simulate();
    const versionStr = domainVersionResult.result;
    
    // Handle "{string:1}" format version number
    if (typeof versionStr === 'string' && versionStr.startsWith('{string:')) {
      return versionStr.substring(8, versionStr.length - 1);
    }
    
    return versionStr;
  } catch (error) {
    console.error("Error getting domain version:", error.message);
    return "1"; // Default value
  }
}

/**
 * Get chain ID
 */
export async function getChainId(vaultClient) {
  try {
    const chainIdOp = await vaultClient.get_eip712_chain_id();
    const chainIdResult = await chainIdOp.simulate();
    return chainIdResult.result;
  } catch (error) {
    console.error("Error getting chain ID:", error.message);
    return Buffer.alloc(32).toString('hex'); // Default value
  }
} 