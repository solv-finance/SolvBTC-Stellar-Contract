import pkg from '@stellar/stellar-sdk';
const { Keypair, hash, nativeToScVal, Address, xdr } = pkg;
import { createHash } from 'crypto';
import { toBufferBE } from 'bigint-buffer';
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
 * @param {string} params.domainName - Domain name
 * @param {string} params.domainVersion - Domain version
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
    domainSeparator, // provided by contract
    requestHash,     // from withdraw_request
    chainId          // hex string (32 bytes)
  } = params;

  console.log("Generating withdraw signature...");
  console.log("User address:", userAddress);
  console.log("Target amount:", targetAmount.toString());
  console.log("Target token:", targetToken);
  console.log("NAV:", nav.toString());
  console.log("Using requestHash from withdraw_request:", Buffer.from(requestHash).toString('hex'));
  
  // Use the provided requestHash instead of generating a new one
  
  // Ensure chainId is hex string
  const chainIdHex = typeof chainId === 'string' ? chainId : Buffer.from(chainId).toString('hex');

  // Create withdraw message
  const withdrawMessage = createWithdrawMessage({
    userAddress,
    targetAmount,
    targetToken,
    nav,
    requestHash,
    chainId: chainIdHex
  });
  
  // Calculate message hash
  const messageHash = sha256(withdrawMessage);
  
  // Create signature message
  const signatureMessage = createSignatureMessage(domainSeparator, messageHash);
  
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
  // For Ed25519, we need an additional sha256 hash on the signature message
  const finalDigest = sha256(signatureMessage);
  const signature = keypair.sign(finalDigest);
  
  console.log("Signature generated successfully");
  
  return {
    signature: signature,
    requestHash: requestHash
  };
}

/**
 * Create withdrawal message - ensure complete consistency with create_withdraw_message in vault contract
 */
export function createWithdrawMessage(params) {
  const {
    userAddress,      // old naming
    targetAmount,     // old naming
    targetToken,      // old naming
    nav,
    requestHash,
    chainId,
    action = "withdraw"
  } = params;

  // Create a buffer to store all fields
  let buffer = Buffer.alloc(0);

  // 1. Add type hash as the first item
  const typeHash = sha256(Buffer.from("Withdraw(uint256 chainId,string action,address user,address withdrawToken,uint256 shares,uint256 nav,bytes32 requestHash)"));
  buffer = Buffer.concat([buffer, typeHash]);

  // 2. Add network ID (chain ID) - already 32 bytes
  buffer = Buffer.concat([buffer, Buffer.from(chainId, 'hex')]);

  // 3. Hash action (dynamic string) before concatenation
  const actionBytes = Buffer.from("withdraw");
  const actionHash = sha256(actionBytes);
  buffer = Buffer.concat([buffer, actionHash]);

  // 4. Hash user address (consistent with calculate_domain_separator)
  const address = new pkg.Address(userAddress);
  const userAddressXDR = nativeToScVal(address).toXDR();
  const userHash = sha256(Buffer.from(userAddressXDR));
  buffer = Buffer.concat([buffer, userHash]);

  // 5. Hash target token address (consistent encoding)
  const targetAddress = new pkg.Address(targetToken);
  const targetTokenXDR = nativeToScVal(targetAddress).toXDR();
  const tokenHash = sha256(Buffer.from(targetTokenXDR));
  buffer = Buffer.concat([buffer, tokenHash]);

  // 6. Add target amount (shares) as fixed 32-byte representation (i128 -> 16 bytes -> left pad to 32)
  const targetAmount32 = encodeI128To32Bytes(BigInt(targetAmount));
  buffer = Buffer.concat([buffer, targetAmount32]);

  // 7. Add NAV value as fixed 32-byte representation (i128 -> 16 bytes -> left pad to 32)
  const nav32 = encodeI128To32Bytes(BigInt(nav));
  buffer = Buffer.concat([buffer, nav32]);

  // 8. Hash request_hash (dynamic bytes) before concatenation
  const requestHashHashed = sha256(requestHash);  // requestHash is already a Buffer
  buffer = Buffer.concat([buffer, requestHashHashed]);

  return buffer;
}

/**
 * Calculate domain separator
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
  
  // 1. Domain TypeHash
  const typeHash = sha256(Buffer.from("Withdraw(uint256 chainId,string action,address user,address withdrawToken,uint256 shares,uint256 nav,bytes32 requestHash)"));
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
 * Create signature message
 */
function createSignatureMessage(domainSeparator, messageHash) {
  // Create a buffer to store all fields
  let buffer = Buffer.alloc(0);
  
  // 1. Add fixed prefix \x19\x01
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

// Encode a non-negative BigInt into big-endian byte array of a fixed length
function encodeI128To32Bytes(value) {
  const be16 = toBufferBE(BigInt(value), 16);
  return Buffer.concat([Buffer.alloc(16), be16]);
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
    const domainSeparatorOp = await vaultClient.get_domain_separator();
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
    const domainNameOp = await vaultClient.get_domain_name();
    const domainNameResult = await domainNameOp.simulate();
    return domainNameResult.result;
  } catch (error) {
    console.error("Error getting domain name:", error.message);
    return "Solv Vault Withdraw"; // Default value
  }
}

/**
 * Get domain version
 */
export async function getDomainVersion(vaultClient) {
  try {
    const domainVersionOp = await vaultClient.get_domain_version();
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
    const chainIdOp = await vaultClient.get_chain_id();
    const chainIdResult = await chainIdOp.simulate();
    return chainIdResult.result;
  } catch (error) {
    console.error("Error getting chain ID:", error.message);
    return Buffer.alloc(32).toString('hex'); // Default value
  }
} 