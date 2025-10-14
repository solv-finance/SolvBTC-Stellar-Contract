import pkg from '@stellar/stellar-sdk';
const { Keypair } = pkg;
import { CONFIG } from './config.js';
import { randomBytes, createHash } from 'crypto'; // Add this line

// sha256 helper
const sha256 = (data) => createHash('sha256').update(data).digest();


// Import contract bindings
import * as fungibleTokenModule from '../../js-bindings/fungible-token/dist/index.js';
import * as vaultModule from '../../js-bindings/vault/dist/index.js';
import * as oracleModule from '../../js-bindings/oracle/dist/index.js';
// Minter manager is now part of fungible token, not a separate contract

import { generateWithdrawSignature, createWithdrawMessage } from './signature-utils.mjs';

// Initialize SDK client
export class StellarContractClient {
  constructor(config) {
    this.config = config;
  }

  // Generate random request hash
  generateRandomRequestHash() {
    return randomBytes(32);
  }

  // Create contract clients
  createTokenClient(contractId) {
    return new fungibleTokenModule.Client({
      contractId: contractId,
      networkPassphrase: this.config.network.networkPassphrase,
      rpcUrl: this.config.network.rpcUrl,
      allowHttp: true
    });
  }

  createVaultClient(contractId) {
    return new vaultModule.Client({
      contractId: contractId,
      networkPassphrase: this.config.network.networkPassphrase,
      rpcUrl: this.config.network.rpcUrl,
      allowHttp: true
    });
  }

  createOracleClient(contractId) {
    return new oracleModule.Client({
      contractId: contractId,
      networkPassphrase: this.config.network.networkPassphrase,
      rpcUrl: this.config.network.rpcUrl,
      allowHttp: true
    });
  }

  // Minter manager is now part of fungible token contract, not a separate contract

  // Initialize token contract
  async initializeToken(secretKey) {
    try {
      console.log("Initializing token contract...");
      const keypair = Keypair.fromSecret(secretKey);
      const tokenClient = this.createTokenClient(this.config.contracts.fungibleToken);
      
      // Check if already initialized
      try {
        const isInitialized = await tokenClient.is_initialized();
        if (isInitialized.result) {
          console.log("Token contract already initialized");
          return true;
        }
      } catch (error) {
        console.log("Error checking initialization status, attempting to initialize");
      }
      
      // Initialize contract
      const initOp = await tokenClient.initialize({
        admin: keypair.publicKey(),
        name: "SolvBTC Token",
        symbol: "SBTC",
        decimals: 8,
        mint_authorization: keypair.publicKey()
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      initOp.sign(keypair);
      const result = await initOp.send();
      console.log("Token contract initialized successfully:", result);
      return true;
    } catch (error) {
      console.error("Error initializing token contract:", error.message);
      return false;
    }
  }

  // Initialize Oracle contract
  async initializeOracle(secretKey) {
    try {
      console.log("Initializing Oracle contract...");
      const keypair = Keypair.fromSecret(secretKey);
      const oracleClient = this.createOracleClient(this.config.contracts.oracle);
      
      // Check if already initialized
      try {
        const isInitialized = await oracleClient.is_initialized();
        if (isInitialized.result) {
          console.log("Oracle contract already initialized");
          return true;
        }
      } catch (error) {
        console.log("Error checking initialization status, attempting to initialize");
      }
      
      // Initialize contract
      const initOp = await oracleClient.initialize({
        admin: keypair.publicKey(),
        nav_decimals: 8,
        initial_nav: BigInt(100000000), // 1.0 with 8 decimals
        max_change_percent: 10 // 10%
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      initOp.sign(keypair);
      const result = await initOp.send();
      console.log("Oracle contract initialized successfully:", result);
      return true;
    } catch (error) {
      console.error("Error initializing Oracle contract:", error.message);
      return false;
    }
  }

  // MinterManager is now part of fungible token, no separate initialization needed

  // Initialize Vault contract
  async initializeVault(secretKey) {
    try {
      console.log("Initializing Vault contract...");
      const keypair = Keypair.fromSecret(secretKey);
      const vaultClient = this.createVaultClient(this.config.contracts.vault);
      
      // Check if already initialized
      try {
        const isInitialized = await vaultClient.is_initialized();
        if (isInitialized.result) {
          console.log("Vault contract already initialized");
          return true;
        }
      } catch (error) {
        console.log("Error checking initialization status, attempting to initialize");
      }
      
      // Initialize contract
      const initOp = await vaultClient.initialize({
        admin: keypair.publicKey(),
        minter_manager: this.config.contracts.minterManager,
        token_contract: this.config.contracts.fungibleToken,
        oracle: this.config.contracts.oracle,
        treasurer: keypair.publicKey(),
        withdraw_verifier: keypair.publicKey(),
        withdraw_fee_ratio: 100,
        withdraw_fee_receiver: keypair.publicKey(), // 1.0 (100%)
        domain_name: "Solv Vault Withdraw",
        domain_version: "1"
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      initOp.sign(keypair);
      const result = await initOp.send();
      console.log("Vault contract initialized successfully:", result);
      return true;
    } catch (error) {
      console.error("Error initializing Vault contract:", error.message);
      return false;
    }
  }

  // Add Vault as a minter
  async addVaultAsMinter(secretKey) {
    try {
      console.log("Adding Vault as a minter...");
      const keypair = Keypair.fromSecret(secretKey);
      const minterManagerClient = this.createMinterManagerClient(this.config.contracts.minterManager);
      
      // Add Vault as a minter
      const addMinterOp = await minterManagerClient.add_minter_by_admin({
        minter: this.config.contracts.vault
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      addMinterOp.sign(keypair);
      const result = await addMinterOp.send();
      console.log("Added Vault as a minter successfully:", result);
      return true;
    } catch (error) {
      console.error("Error adding Vault as a minter:", error.message);
      return false;
    }
  }

  // Add supported currency
  async addCurrency(secretKey, currencyAddress) {
    try {
      console.log("Adding supported currency...");
      const keypair = Keypair.fromSecret(secretKey);
      const vaultClient = this.createVaultClient(this.config.contracts.vault);
      
      // Check if currency already exists
      try {
        // Try to get the list of supported currencies
        const currenciesOp = await vaultClient.get_supported_currencies({}, {
          fee: 100000,
          timeoutInSeconds: 30
        });
        
        // Simulate transaction
        const currenciesResult = await currenciesOp.simulate();
        const currencies = currenciesResult.result;
        
        // Check if currency is already in the list
        if (currencies.includes(currencyAddress)) {
          console.log("Currency already supported, no need to add again");
          return true;
        }
      } catch (error) {
        console.log("Error checking supported currencies, attempting to add currency");
      }
      
      // Add currency
      const addCurrencyOp = await vaultClient.add_currency_by_admin({
        currency: currencyAddress
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      // Sign and send transaction
      addCurrencyOp.sign(keypair);
      const addResult = await addCurrencyOp.send();
      console.log("Currency added successfully:", addResult);
      
      // Currency is now added and ready to use
      return true;
    } catch (error) {
      console.error("Error adding currency:", error.message);
      return false;
    }
  }

  // Deposit to vault
  async deposit(secretKey, currencyAddress, amount) {
    try {
      console.log("Depositing to vault...");
      console.log("Using currency address:", currencyAddress);
      console.log("Deposit amount:", amount);
      
      const keypair = Keypair.fromSecret(secretKey);
      console.log("User address:", keypair.publicKey());
      console.log("Vault address:", this.config.contracts.vault);
      console.log("Network passphrase:", this.config.network.networkPassphrase);
      
      const signer = pkg.contract.basicNodeSigner(keypair, this.config.network.networkPassphrase);
      // Create token contract client
      const tokenClient = new fungibleTokenModule.Client({
        contractId: currencyAddress,
        networkPassphrase: this.config.network.networkPassphrase,
        rpcUrl: this.config.network.rpcUrl,
        allowHttp: true,
        publicKey: keypair.publicKey(),
        signTransaction: signer.signTransaction,
      });
      
      // Check balance
      const balanceResult = await tokenClient.balance({
        account: keypair.publicKey()
      });
      console.log("Current balance:", balanceResult.result.toString());
      
      if (BigInt(balanceResult.result) < BigInt(amount)) {
        console.error("Insufficient balance, cannot deposit");
        return false;
      }
      
      // Check allowance
      const allowanceResult = await tokenClient.allowance({
        owner: keypair.publicKey(),
        spender: this.config.contracts.vault
      });
      console.log("Current allowance:", allowanceResult.result.toString());
      
      // If allowance is insufficient, re-approve
      if (BigInt(allowanceResult.result) < BigInt(amount)) {
        console.log("Insufficient allowance, re-approving...");

        // Get current ledger for expiration
        const server = new pkg.rpc.Server(this.config.network.rpcUrl);
        const ledgerInfo = await server.getLatestLedger();
        const currentLedger = ledgerInfo.sequence;

        // Build approve operation with correct parameter format
        const approveOp = await tokenClient.approve({
          owner: keypair.publicKey(),
          spender: this.config.contracts.vault,
          amount: amount.toString(),  // Use string instead of BigInt
          live_until_ledger: currentLedger + 10000
        }, {
          fee: "10000",  // Use string for fee
          timeoutInSeconds: 30
        });
        
        // Simulate transaction
        try {
          const simulationResult = await approveOp.simulate();
          console.log("Approve simulation result:");
        } catch (simError) {
          console.log("Approve simulation error:", simError.message);
        }
        
        
        // Send transaction
        try {
          const approveResult = await approveOp.signAndSend();
          console.log("Approve successful:");
        } catch (sendError) {
          console.error("Approve send error:", sendError);
          if (sendError.message.includes("NeedsMoreSignaturesError")) {
            console.error("Needs more signatures, please check if you have sufficient permissions");
          }
          return false;
        }
      }
      
      console.log("Preparing deposit...");
      
      // Create vault contract client
      const vaultClient = new vaultModule.Client({
        contractId: this.config.contracts.vault,
        networkPassphrase: this.config.network.networkPassphrase,
        rpcUrl: this.config.network.rpcUrl,
        allowHttp: true,
        publicKey: keypair.publicKey(),
        signTransaction: signer.signTransaction,
      });
      
      // Build deposit operation with correct parameter format
      const depositOp = await vaultClient.deposit({
        from: keypair.publicKey(),
        currency: currencyAddress,
        amount: amount.toString()  // Use string instead of BigInt
      }, {
        fee: "100000",  // Use string for fee
        timeoutInSeconds: 30
      });
      console.log("from:",keypair.publicKey());
      // Simulate transaction
      try {
        const simulationResult = await depositOp.simulate();
        console.log("Deposit simulation result:");
      } catch (simError) {
        console.log("Deposit simulation error:", simError.message);
        console.log("Full error:", simError);
        throw simError; // Re-throw to see full stack trace
      }
      
      // Sign transaction
      
      // Send transaction
      try {
        const depositResult = await depositOp.signAndSend();
        console.log("Deposit successful:", depositResult);
        return true;
      } catch (sendError) {
        console.error("Deposit send error:", sendError);
        if (sendError.message.includes("NeedsMoreSignaturesError")) {
          console.error("Needs more signatures, please check if you have sufficient permissions");
        }
        return false;
      }
    } catch (error) {
      console.error("Deposit error:", error.message);
      return false;
    }
  }

  // Withdraw - New two-step process
  async withdraw(secretKey, shares) {
    try {
      console.log("Starting two-step withdraw process...");
      console.log("Withdraw shares:", shares.toString());
      
      const keypair = Keypair.fromSecret(secretKey);
      const signer = pkg.contract.basicNodeSigner(keypair, this.config.network.networkPassphrase);
      
      // Create vault contract client
      const vaultClient = new vaultModule.Client({
        contractId: this.config.contracts.vault,
        networkPassphrase: this.config.network.networkPassphrase,
        rpcUrl: this.config.network.rpcUrl,
        allowHttp: true,
        publicKey: keypair.publicKey(),
        signTransaction: signer.signTransaction,
      });
      
      // Create oracle contract client
      const oracleClient = new oracleModule.Client({
        contractId: this.config.contracts.oracle,
        networkPassphrase: this.config.network.networkPassphrase,
        rpcUrl: this.config.network.rpcUrl,
        allowHttp: true,
      });
      
      // Get current NAV
      const navResult = await oracleClient.get_nav();
      const nav = navResult.result;
      console.log("Current NAV:", nav.toString());
      
      // Generate request hash
      const requestHash = this.generateRandomRequestHash();
      console.log("Generated request hash:", Buffer.from(requestHash).toString('hex'));
      
      console.log("\n===== Step 1: withdraw_request =====");

      // use approve to transfer shares to vault
      const tokenClient = new fungibleTokenModule.Client({
        contractId: this.config.contracts.fungibleToken,
        networkPassphrase: this.config.network.networkPassphrase,
        rpcUrl: this.config.network.rpcUrl,
        allowHttp: true,
        publicKey: keypair.publicKey(),
        signTransaction: signer.signTransaction,
      });
      // Get current ledger from the network
      const server = new pkg.rpc.Server(this.config.network.rpcUrl);
      const ledgerInfo = await server.getLatestLedger();
      const currentLedger = ledgerInfo.sequence;
      console.log("Current ledger:", currentLedger);

      const approveOp = await tokenClient.approve({
        owner: keypair.publicKey(),
        spender: this.config.contracts.vault,
        amount: shares.toString(),  // Convert to string
        live_until_ledger: currentLedger + 10000
      });

      try {
        const approveResult = await approveOp.signAndSend();
        console.log("Approve successful:", approveResult);
      } catch (sendError) {
        console.error("Approve send error:", sendError);
        if (sendError.message.includes("NeedsMoreSignaturesError")) {
          console.error("Needs more signatures, please check if you have sufficient permissions");
        }
        return false;
      }

      
      // Step 1: Create withdraw request
      const withdrawRequestOp = await vaultClient.withdraw_request({
        from: keypair.publicKey(),
        shares: BigInt(shares),
        request_hash: requestHash
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      // Send withdraw request
      try {
        const requestResult = await withdrawRequestOp.signAndSend();
        console.log("Withdraw request created successfully:", requestResult);
      } catch (requestError) {
        console.error("Withdraw request failed:", requestError.message);
        return false;
      }

      console.log("\n===== Step 2: treasurer deposit (skipping - vault already funded) =====")
      console.log("Vault has been pre-funded with TestCoin, skipping treasurer_deposit step...");
      
      console.log("\n===== Step 3: withdraw =====");
      
      // Get withdraw currency and domain info for signature
      const withdrawCurrencyOp = await vaultClient.get_withdraw_currency();
      const withdrawCurrencyResult = await withdrawCurrencyOp.simulate();
      const targetToken = withdrawCurrencyResult.result;
      console.log("Withdraw currency:", targetToken);
      
      const domainSeparatorOp = await vaultClient.get_domain_separator();
      const domainSeparatorResult = await domainSeparatorOp.simulate();
      const domainSeparator = domainSeparatorResult.result;

      // Get chain ID
      const chainIdOp = await vaultClient.get_chain_id();
      const chainIdResult = await chainIdOp.simulate();
      const chainId = chainIdResult.result;

      // Get current timestamp
      const timestamp = Math.floor(Date.now() / 1000);

      // Generate signature for withdraw using admin key
      // For Ed25519 signature, we need to use the admin key (withdraw_verifier)
      if (!this.config.accounts?.admin?.secretKey || this.config.accounts.admin.secretKey === '') {
        console.error("Admin key not configured for withdraw signature. Set ADMIN_SECRET_KEY environment variable.");
        return false;
      }

      const adminKeypair = Keypair.fromSecret(this.config.accounts.admin.secretKey);

      // Normalize chainId to hex string (createWithdrawMessage expects hex string)
      const chainIdHex = Buffer.isBuffer(chainId)
        ? Buffer.from(chainId).toString('hex')
        : (typeof chainId === 'string' ? chainId : Buffer.from(chainId).toString('hex'));

      // Create the withdraw message to sign (matching the contract's create_withdraw_message)
      const withdrawMessage = createWithdrawMessage({
        chainId: chainIdHex,
        action: "withdraw",
        userAddress: keypair.publicKey(),
        targetToken: targetToken,
        targetAmount: BigInt(shares),
        nav: BigInt(nav),
        requestHash: requestHash
      });

      // Align with contract: digest = sha256( 0x19 0x01 || domainSeparator || sha256(withdrawMessage) )
      const messageHash = sha256(withdrawMessage);
      const dsBuf = Buffer.isBuffer(domainSeparator)
        ? domainSeparator
        : (typeof domainSeparator === 'string' ? Buffer.from(domainSeparator, 'hex') : Buffer.from(domainSeparator));
      const signatureMessage = Buffer.concat([Buffer.from([0x19, 0x01]), dsBuf, messageHash]);
      const digest = sha256(signatureMessage);
      const signature = adminKeypair.sign(digest);

      const signatureData = {
        signature: signature,
        requestHash: requestHash.toString('hex')
      };
      
      console.log("Signature data:", {
        requestHash: Buffer.from(requestHash).toString('hex'),
        signature: Buffer.from(signatureData.signature).toString('hex')
      });
      
      // Step 2: Complete withdraw
      const withdrawOp = await vaultClient.withdraw({
        from: keypair.publicKey(),
        shares: BigInt(shares),     // Use shares parameter
        nav: nav,
        request_hash: requestHash,  // Must match step 1
        signature: signatureData.signature,
        signature_type: 0,  // 0 for Ed25519
        recovery_id: 0      // Not used for Ed25519, but required
      }, {
        fee: 100000,
        timeoutInSeconds: 30
      });
      
      // Simulate transaction
      try {
        const simulationResult = await withdrawOp.simulate();
        console.log("Withdraw simulation result:", simulationResult);
      } catch (simError) {
        console.log("Withdraw simulation error:", simError.message);
      }
      
      // Send withdraw transaction
      try {
        const withdrawResult = await withdrawOp.signAndSend();
        console.log("Withdraw completed successfully:", withdrawResult);
        return true;
      } catch (sendError) {
        console.error("Withdraw failed:", sendError.message);
        if (sendError.message.includes("NeedsMoreSignaturesError")) {
          console.error("Needs more signatures, please check if you have sufficient permissions");
        }
        return false;
      }
      
    } catch (error) {
      console.error("Withdraw error:", error.message);
      return false;
    }
  }

  // Query token info
  async getTokenInfo() {
    try {
      console.log("Querying token info...");
      const tokenClient = this.createTokenClient(this.config.contracts.fungibleToken);
      
      const nameResult = await tokenClient.name();
      const symbolResult = await tokenClient.symbol();
      const decimalsResult = await tokenClient.decimals();
      
      console.log("Token name:", nameResult.result);
      console.log("Token symbol:", symbolResult.result);
      console.log("Token decimals:", decimalsResult.result);
      
      return {
        name: nameResult.result,
        symbol: symbolResult.result,
        decimals: decimalsResult.result
      };
    } catch (error) {
      console.error("Error querying token info:", error.message);
      return null;
    }
  }

  // Query vault info
  async getVaultInfo() {
    try {
      console.log("Querying vault info...");
      const vaultClient = this.createVaultClient(this.config.contracts.vault);
      
      const adminResult = await vaultClient.admin();
      console.log("Vault admin:", adminResult.result);
      
      return {
        admin: adminResult.result
      };
    } catch (error) {
      console.error("Error querying vault info:", error.message);
      return null;
    }
  }

  // Query oracle price
  async getOraclePrice() {
    try {
      console.log("Querying oracle price...");
      const oracleClient = this.createOracleClient(this.config.contracts.oracle);
      
      const navResult = await oracleClient.get_nav();
      const navDecimalsResult = await oracleClient.get_nav_decimals();
      
      console.log("Oracle NAV:", navResult.result);
      console.log("Oracle NAV decimals:", navDecimalsResult.result);
      
      return {
        nav: navResult.result,
        navDecimals: navDecimalsResult.result
      };
    } catch (error) {
      console.error("Error querying oracle price:", error.message);
      return null;
    }
  }
}

// Main function
async function main() {
  // Create client
  const client = new StellarContractClient(CONFIG);
  
  // Query info
  console.log("\n===== Querying contract info =====");
  await client.getTokenInfo();
  await client.getVaultInfo();
  await client.getOraclePrice();
  
  // Check if we can perform write operations (need deployer key for testing)
  if (CONFIG.accounts.deployer && CONFIG.accounts.deployer.secretKey && CONFIG.accounts.deployer.secretKey !== 'YOUR_DEPLOYER_SECRET_KEY_HERE') {
    // Query minter info (now part of fungible token contract)
    console.log("\n===== Querying minter info =====");
    try {
      const tokenClient = client.createTokenClient(CONFIG.contracts.fungibleToken);
      const mintersOp = await tokenClient.get_minters();
      const mintersResult = await mintersOp.simulate();
      console.log("Current minter list:", mintersResult.result);
      
      // Check if vault is already a minter
      const isVaultMinter = mintersResult.result.includes(CONFIG.contracts.vault);
      console.log("Is Vault a minter:", isVaultMinter);
    } catch (error) {
      console.error("Error querying minter info:", error.message);
    }
    
    // Query supported currencies
    console.log("\n===== Querying supported currencies =====");
    const vaultClient = client.createVaultClient(CONFIG.contracts.vault);
    try {
      const currenciesOp = await vaultClient.get_supported_currencies();
      const currenciesResult = await currenciesOp.simulate();
      console.log("Supported currencies:", currenciesResult.result);
      
      if (currenciesResult.result.length > 0) {
        // Use the first supported currency for deposit test
        const testCurrencyAddress = currenciesResult.result[0];
        
        // 6. Deposit
        console.log("\n===== Deposit test =====");
        console.log("Using currency address:", testCurrencyAddress);
        await client.deposit(CONFIG.accounts.deployer.secretKey, testCurrencyAddress, 5000000); // 0.05 WBTC
        
        // 7. Withdraw (now a two-step process)
        console.log("\n===== Withdraw test =====");
        // Parameter is number of shares, not final withdrawal amount
        await client.withdraw(CONFIG.accounts.deployer.secretKey, 2500000); // Withdraw part of deposited amount
      } else {
        console.log("No supported currencies, cannot perform deposit and withdraw tests");
      }
    } catch (error) {
      console.error("Error querying supported currencies:", error.message);
    }
  } else {
    console.log("\nNote: Deployer key not provided, only query operations will be performed. If you want to perform write operations, please configure the deployer key in config.js.");
  }
}

// Only run main if this file is executed directly, not imported
if (import.meta.url === `file://${process.argv[1]}`) {
  main()
    .then(() => console.log("\n===== Example run completed ====="))
    .catch(error => console.error("Run error:", error));
} 