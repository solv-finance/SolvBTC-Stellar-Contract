import pkg from '@stellar/stellar-sdk';
const { Keypair } = pkg;
import { CONFIG } from './config.js';

// Import contract bindings
import * as minterManagerModule from '../../js-bindings/minter-manager/dist/index.js';

async function queryMinters() {
  try {
    console.log("Querying minters list from minter-manager contract...");
    console.log("minter-manager contract address:", CONFIG.contracts.minterManager);
    
    // Create minter-manager contract client
    const minterManagerClient = new minterManagerModule.Client({
      contractId: CONFIG.contracts.minterManager,
      networkPassphrase: CONFIG.network.networkPassphrase,
      rpcUrl: CONFIG.network.rpcUrl,
      allowHttp: true
    });
    
    // Query minters list
    const mintersOp = await minterManagerClient.get_minters();
    const mintersResult = await mintersOp.simulate();
    console.log("Current minters list:", mintersResult.result);
    
    // Query token contract address
    const tokenContractOp = await minterManagerClient.token_contract();
    const tokenContractResult = await tokenContractOp.simulate();
    console.log("Token contract address:", tokenContractResult.result);
    
    // Query admin address
    const adminOp = await minterManagerClient.admin();
    const adminResult = await adminOp.simulate();
    console.log("Admin address:", adminResult.result);
    
    // Check if vault is a minter
    const isVaultMinterOp = await minterManagerClient.is_minter({
      address: CONFIG.contracts.vault
    });
    const isVaultMinterResult = await isVaultMinterOp.simulate();
    console.log("Is vault a minter:", isVaultMinterResult.result);
    
    return {
      minters: mintersResult.result,
      tokenContract: tokenContractResult.result,
      admin: adminResult.result,
      isVaultMinter: isVaultMinterResult.result
    };
  } catch (error) {
    console.error("Error querying minters:", error.message);
    return null;
  }
}

// Run the query
queryMinters()
  .then(result => {
    if (result) {
      console.log("\n===== Query Result Summary =====");
      console.log("Number of minters:", result.minters.length);
      console.log("Minters list:", result.minters);
      console.log("Token contract address:", result.tokenContract);
      console.log("Admin address:", result.admin);
      console.log("Is vault a minter:", result.isVaultMinter);
    }
  })
  .catch(error => console.error("Runtime error:", error)); 