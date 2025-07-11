export const CONFIG = {
  // Local network configuration
  network: {
    networkPassphrase: "Test SDF Network ; September 2015",
    rpcUrl: "http://localhost:8000/soroban/rpc",
  },
  // Contract IDs
  contracts: {
    fungibleToken: "CAPQXPPAIUDIJRRDXLUAIY4QRG5QCJN2B5SFGQOGB6GPBSXKK6GX2ZKQ",
    vault: "CB22PCIBZJQMEO7KLV4WUWDG7N6BRQ6QN3ALYGOUYO3ZPLVC2CS5V46K",
    oracle: "CBMKIQH4PJ6LN7DVG2G7TJLGPJUDOWGIH2UY5ULOGDAHKBSWMOXC3FMM",
    minterManager: "CDRQZFAHFFYYVHRAQE7M4LNR2UZUZNVOEA4T2QQP4MYOXEN5GEIIXIWI",
  },
  // Account keypairs
  accounts: {
    bob: {
      publicKey: "GCDSLQQIC6OE5VW63EZMRMGA5TEQ7TAICN5TDMCJARRLYPQQNZW6EZEC",
      // Note: In a real application, never hardcode private keys in code
      // This is for demonstration purposes only
      secretKey: "SBDWQEXHWMEUGTBX57B7XUNICVVRP6BHUUN6MHJO4RENT3JXPQGIU3QW" // Bob account's private key
    },
    admin: {
      publicKey: "GCDSLQQIC6OE5VW63EZMRMGA5TEQ7TAICN5TDMCJARRLYPQQNZW6EZEC",
      // Note: In a real application, never hardcode private keys in code
      // This is for demonstration purposes only
      secretKey: "SBDWQEXHWMEUGTBX57B7XUNICVVRP6BHUUN6MHJO4RENT3JXPQGIU3QW" // Using Bob account as admin
    }
  }
}; 