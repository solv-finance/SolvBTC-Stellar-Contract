import { Buffer } from "buffer";
import { Address } from '@stellar/stellar-sdk';
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from '@stellar/stellar-sdk/contract';
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Typepoint,
  Duration,
} from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk'
export * as contract from '@stellar/stellar-sdk/contract'
export * as rpc from '@stellar/stellar-sdk/rpc'

if (typeof window !== 'undefined') {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}





/**
 * EIP712 signature data structure: withdrawal request
 */
export interface WithdrawRequest {
  nav: i128;
  request_hash: Buffer;
  signature: Buffer;
  target_amount: i128;
  timestamp: u64;
  user: string;
}


/**
 * Deposit event
 */
export interface DepositEvent {
  amount: i128;
  currency: string;
  minted_tokens: i128;
  nav: i128;
  token_contract: string;
  user: string;
}


/**
 * Withdrawal event
 */
export interface WithdrawEvent {
  actual_amount: i128;
  burned_tokens: i128;
  fee_amount: i128;
  from: string;
  gross_amount: i128;
  nav: i128;
  request_hash: Buffer;
  target_amount: i128;
}


/**
 * Currency added event
 */
export interface CurrencyAddedEvent {
  admin: string;
  currency: string;
}


/**
 * Currency removed event
 */
export interface CurrencyRemovedEvent {
  admin: string;
  currency: string;
}

/**
 * Storage data key enum
 */
export type DataKey = {tag: "Admin", values: void} | {tag: "Initialized", values: void} | {tag: "MinterManager", values: void} | {tag: "Oracle", values: void} | {tag: "Treasurer", values: void} | {tag: "WithdrawVerifier", values: void} | {tag: "TokenContract", values: void} | {tag: "SupportedCurrencies", values: void} | {tag: "WithdrawCurrency", values: void} | {tag: "WithdrawRatio", values: void} | {tag: "FeeCollector", values: void} | {tag: "MinimumFee", values: void} | {tag: "UsedRequestHash", values: readonly [Buffer]} | {tag: "EIP712DomainName", values: void} | {tag: "EIP712DomainVersion", values: void};


export interface EIP712Domain {
  chain_id: Buffer;
  name: string;
  salt: Buffer;
  verifying_contract: string;
  version: string;
}

/**
 * Error code definition
 */
export const VaultError = {
  /**
   * Permission insufficient
   */
  1: {message:"Unauthorized"},
  /**
   * Invalid parameter
   */
  2: {message:"InvalidArgument"},
  /**
   * Contract not initialized
   */
  3: {message:"NotInitialized"},
  /**
   * Contract already initialized
   */
  4: {message:"AlreadyInitialized"},
  /**
   * Currency not supported
   */
  5: {message:"CurrencyNotSupported"},
  /**
   * Exceeds maximum currency quantity
   */
  6: {message:"TooManyCurrencies"},
  /**
   * Currency already exists
   */
  7: {message:"CurrencyAlreadyExists"},
  /**
   * Currency does not exist
   */
  8: {message:"CurrencyNotExists"},
  /**
   * Invalid amount
   */
  9: {message:"InvalidAmount"},
  /**
   * Oracle not set
   */
  10: {message:"OracleNotSet"},
  /**
   * Minter Manager not set
   */
  11: {message:"MinterManagerNotSet"},
  /**
   * Treasurer not set
   */
  12: {message:"TreasurerNotSet"},
  /**
   * Withdrawal verifier not set
   */
  13: {message:"WithdrawVerifierNotSet"},
  /**
   * Withdrawal currency not set
   */
  14: {message:"WithdrawCurrencyNotSet"},
  /**
   * Signature verification failed
   */
  15: {message:"InvalidSignature"},
  /**
   * Request hash already used
   */
  16: {message:"RequestHashAlreadyUsed"},
  /**
   * Invalid NAV
   */
  17: {message:"InvalidNav"},
  /**
   * Invalid withdraw fee ratio
   */
  18: {message:"InvalidWithdrawRatio"},
  /**
   * Fee collector address not set
   */
  19: {message:"FeeCollectorNotSet"},
  /**
   * NAV value expired
   */
  20: {message:"StaleNavValue"},
  /**
   * Invalid fee amount
   */
  21: {message:"InvalidFeeAmount"},
  /**
   * Token contract not set
   */
  22: {message:"TokenContractNotSet"},
  /**
   * Invalid signature format
   */
  23: {message:"InvalidSignatureFormat"}
}

export interface Client {
  /**
   * Construct and simulate a initialize transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  initialize: ({admin, minter_manager, token_contract, oracle, treasurer, withdraw_verifier, withdraw_ratio, eip712_domain_name, eip712_domain_version}: {admin: string, minter_manager: string, token_contract: string, oracle: string, treasurer: string, withdraw_verifier: string, withdraw_ratio: i128, eip712_domain_name: string, eip712_domain_version: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a deposit transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  deposit: ({from, currency, amount}: {from: string, currency: string, amount: i128}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a withdraw transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  withdraw: ({from, target_amount, nav, request_hash, timestamp, signature}: {from: string, target_amount: i128, nav: i128, request_hash: Buffer, timestamp: u64, signature: Buffer}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a treasurer_deposit transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  treasurer_deposit: ({amount}: {amount: i128}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_currency_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_currency_by_admin: ({currency}: {currency: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a remove_currency_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  remove_currency_by_admin: ({currency}: {currency: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_withdraw_currency_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_withdraw_currency_by_admin: ({currency}: {currency: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_supported_currencies transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_supported_currencies: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Array<string>>>

  /**
   * Construct and simulate a is_currency_supported transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  is_currency_supported: ({currency}: {currency: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a get_withdraw_currency transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_withdraw_currency: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Option<string>>>

  /**
   * Construct and simulate a set_withdraw_verifier_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_withdraw_verifier_by_admin: ({verifier_address}: {verifier_address: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_oracle_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_oracle_by_admin: ({oracle}: {oracle: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_treasurer_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_treasurer_by_admin: ({treasurer}: {treasurer: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_minter_manager_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_minter_manager_by_admin: ({minter_manager}: {minter_manager: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_withdraw_ratio_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_withdraw_ratio_by_admin: ({withdraw_ratio}: {withdraw_ratio: i128}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_eip712_domain_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_eip712_domain_by_admin: ({name, version}: {name: string, version: string}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  admin: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_withdraw_verifier transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_withdraw_verifier: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_oracle transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_oracle: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_treasurer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_treasurer: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_minter_manager transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_minter_manager: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_withdraw_ratio transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_withdraw_ratio: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a is_initialized transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  is_initialized: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a get_eip712_domain_name transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_eip712_domain_name: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_eip712_domain_version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_eip712_domain_version: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a get_eip712_chain_id transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_eip712_chain_id: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Buffer>>

  /**
   * Construct and simulate a get_eip712_domain_separator transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_eip712_domain_separator: (options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Buffer>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(null, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAQAAADNFSVA3MTIgc2lnbmF0dXJlIGRhdGEgc3RydWN0dXJlOiB3aXRoZHJhd2FsIHJlcXVlc3QAAAAAAAAAAA9XaXRoZHJhd1JlcXVlc3QAAAAABgAAAAAAAAADbmF2AAAAAAsAAAAAAAAADHJlcXVlc3RfaGFzaAAAAA4AAAAAAAAACXNpZ25hdHVyZQAAAAAAAA4AAAAAAAAADXRhcmdldF9hbW91bnQAAAAAAAALAAAAAAAAAAl0aW1lc3RhbXAAAAAAAAAGAAAAAAAAAAR1c2VyAAAAEw==",
        "AAAAAQAAAA1EZXBvc2l0IGV2ZW50AAAAAAAAAAAAAAxEZXBvc2l0RXZlbnQAAAAGAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAACGN1cnJlbmN5AAAAEwAAAAAAAAANbWludGVkX3Rva2VucwAAAAAAAAsAAAAAAAAAA25hdgAAAAALAAAAAAAAAA50b2tlbl9jb250cmFjdAAAAAAAEwAAAAAAAAAEdXNlcgAAABM=",
        "AAAAAQAAABBXaXRoZHJhd2FsIGV2ZW50AAAAAAAAAA1XaXRoZHJhd0V2ZW50AAAAAAAACAAAAAAAAAANYWN0dWFsX2Ftb3VudAAAAAAAAAsAAAAAAAAADWJ1cm5lZF90b2tlbnMAAAAAAAALAAAAAAAAAApmZWVfYW1vdW50AAAAAAALAAAAAAAAAARmcm9tAAAAEwAAAAAAAAAMZ3Jvc3NfYW1vdW50AAAACwAAAAAAAAADbmF2AAAAAAsAAAAAAAAADHJlcXVlc3RfaGFzaAAAAA4AAAAAAAAADXRhcmdldF9hbW91bnQAAAAAAAAL",
        "AAAAAQAAABRDdXJyZW5jeSBhZGRlZCBldmVudAAAAAAAAAASQ3VycmVuY3lBZGRlZEV2ZW50AAAAAAACAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAACGN1cnJlbmN5AAAAEw==",
        "AAAAAQAAABZDdXJyZW5jeSByZW1vdmVkIGV2ZW50AAAAAAAAAAAAFEN1cnJlbmN5UmVtb3ZlZEV2ZW50AAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAhjdXJyZW5jeQAAABM=",
        "AAAAAgAAABVTdG9yYWdlIGRhdGEga2V5IGVudW0AAAAAAAAAAAAAB0RhdGFLZXkAAAAADwAAAAAAAAAOQ29udHJhY3QgYWRtaW4AAAAAAAVBZG1pbgAAAAAAAAAAAAAVSW5pdGlhbGl6YXRpb24gc3RhdHVzAAAAAAAAC0luaXRpYWxpemVkAAAAAAAAAAAfTWludGVyIE1hbmFnZXIgY29udHJhY3QgYWRkcmVzcwAAAAANTWludGVyTWFuYWdlcgAAAAAAAAAAAAAXT3JhY2xlIGNvbnRyYWN0IGFkZHJlc3MAAAAABk9yYWNsZQAAAAAAAAAAABFUcmVhc3VyZXIgYWRkcmVzcwAAAAAAAAlUcmVhc3VyZXIAAAAAAAAAAAAAG1dpdGhkcmF3YWwgdmVyaWZpZXIgYWRkcmVzcwAAAAAQV2l0aGRyYXdWZXJpZmllcgAAAAAAAAAWVG9rZW4gY29udHJhY3QgYWRkcmVzcwAAAAAADVRva2VuQ29udHJhY3QAAAAAAAAAAAAAMVN1cHBvcnRlZCBjdXJyZW5jaWVzIG1hcHBpbmcgKE1hcDxBZGRyZXNzLCBib29sPikAAAAAAAATU3VwcG9ydGVkQ3VycmVuY2llcwAAAAAAAAAAE1dpdGhkcmF3YWwgY3VycmVuY3kAAAAAEFdpdGhkcmF3Q3VycmVuY3kAAAAAAAAAFFdpdGhkcmF3YWwgZmVlIHJhdGlvAAAADVdpdGhkcmF3UmF0aW8AAAAAAAAAAAAAFUZlZSBjb2xsZWN0b3IgYWRkcmVzcwAAAAAAAAxGZWVDb2xsZWN0b3IAAAAAAAAAEk1pbmltdW0gZmVlIGFtb3VudAAAAAAACk1pbmltdW1GZWUAAAAAAAEAAAAqVXNlZCByZXF1ZXN0IGhhc2ggKHByZXZlbnQgcmVwbGF5IGF0dGFja3MpAAAAAAAPVXNlZFJlcXVlc3RIYXNoAAAAAAEAAAAOAAAAAAAAABJFSVA3MTIgRG9tYWluIG5hbWUAAAAAABBFSVA3MTJEb21haW5OYW1lAAAAAAAAABVFSVA3MTIgRG9tYWluIHZlcnNpb24AAAAAAAATRUlQNzEyRG9tYWluVmVyc2lvbgA=",
        "AAAAAQAAAAAAAAAAAAAADEVJUDcxMkRvbWFpbgAAAAUAAAAAAAAACGNoYWluX2lkAAAADgAAAAAAAAAEbmFtZQAAABAAAAAAAAAABHNhbHQAAAAOAAAAAAAAABJ2ZXJpZnlpbmdfY29udHJhY3QAAAAAABMAAAAAAAAAB3ZlcnNpb24AAAAAEA==",
        "AAAABAAAABVFcnJvciBjb2RlIGRlZmluaXRpb24AAAAAAAAAAAAAClZhdWx0RXJyb3IAAAAAABcAAAAXUGVybWlzc2lvbiBpbnN1ZmZpY2llbnQAAAAADFVuYXV0aG9yaXplZAAAAAEAAAARSW52YWxpZCBwYXJhbWV0ZXIAAAAAAAAPSW52YWxpZEFyZ3VtZW50AAAAAAIAAAAYQ29udHJhY3Qgbm90IGluaXRpYWxpemVkAAAADk5vdEluaXRpYWxpemVkAAAAAAADAAAAHENvbnRyYWN0IGFscmVhZHkgaW5pdGlhbGl6ZWQAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAAEAAAAFkN1cnJlbmN5IG5vdCBzdXBwb3J0ZWQAAAAAABRDdXJyZW5jeU5vdFN1cHBvcnRlZAAAAAUAAAAhRXhjZWVkcyBtYXhpbXVtIGN1cnJlbmN5IHF1YW50aXR5AAAAAAAAEVRvb01hbnlDdXJyZW5jaWVzAAAAAAAABgAAABdDdXJyZW5jeSBhbHJlYWR5IGV4aXN0cwAAAAAVQ3VycmVuY3lBbHJlYWR5RXhpc3RzAAAAAAAABwAAABdDdXJyZW5jeSBkb2VzIG5vdCBleGlzdAAAAAARQ3VycmVuY3lOb3RFeGlzdHMAAAAAAAAIAAAADkludmFsaWQgYW1vdW50AAAAAAANSW52YWxpZEFtb3VudAAAAAAAAAkAAAAOT3JhY2xlIG5vdCBzZXQAAAAAAAxPcmFjbGVOb3RTZXQAAAAKAAAAFk1pbnRlciBNYW5hZ2VyIG5vdCBzZXQAAAAAABNNaW50ZXJNYW5hZ2VyTm90U2V0AAAAAAsAAAARVHJlYXN1cmVyIG5vdCBzZXQAAAAAAAAPVHJlYXN1cmVyTm90U2V0AAAAAAwAAAAbV2l0aGRyYXdhbCB2ZXJpZmllciBub3Qgc2V0AAAAABZXaXRoZHJhd1ZlcmlmaWVyTm90U2V0AAAAAAANAAAAG1dpdGhkcmF3YWwgY3VycmVuY3kgbm90IHNldAAAAAAWV2l0aGRyYXdDdXJyZW5jeU5vdFNldAAAAAAADgAAAB1TaWduYXR1cmUgdmVyaWZpY2F0aW9uIGZhaWxlZAAAAAAAABBJbnZhbGlkU2lnbmF0dXJlAAAADwAAABlSZXF1ZXN0IGhhc2ggYWxyZWFkeSB1c2VkAAAAAAAAFlJlcXVlc3RIYXNoQWxyZWFkeVVzZWQAAAAAABAAAAALSW52YWxpZCBOQVYAAAAACkludmFsaWROYXYAAAAAABEAAAAaSW52YWxpZCB3aXRoZHJhdyBmZWUgcmF0aW8AAAAAABRJbnZhbGlkV2l0aGRyYXdSYXRpbwAAABIAAAAdRmVlIGNvbGxlY3RvciBhZGRyZXNzIG5vdCBzZXQAAAAAAAASRmVlQ29sbGVjdG9yTm90U2V0AAAAAAATAAAAEU5BViB2YWx1ZSBleHBpcmVkAAAAAAAADVN0YWxlTmF2VmFsdWUAAAAAAAAUAAAAEkludmFsaWQgZmVlIGFtb3VudAAAAAAAEEludmFsaWRGZWVBbW91bnQAAAAVAAAAFlRva2VuIGNvbnRyYWN0IG5vdCBzZXQAAAAAABNUb2tlbkNvbnRyYWN0Tm90U2V0AAAAABYAAAAYSW52YWxpZCBzaWduYXR1cmUgZm9ybWF0AAAAFkludmFsaWRTaWduYXR1cmVGb3JtYXQAAAAAABc=",
        "AAAAAAAAAAAAAAAKaW5pdGlhbGl6ZQAAAAAACQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAA5taW50ZXJfbWFuYWdlcgAAAAAAEwAAAAAAAAAOdG9rZW5fY29udHJhY3QAAAAAABMAAAAAAAAABm9yYWNsZQAAAAAAEwAAAAAAAAAJdHJlYXN1cmVyAAAAAAAAEwAAAAAAAAARd2l0aGRyYXdfdmVyaWZpZXIAAAAAAAATAAAAAAAAAA53aXRoZHJhd19yYXRpbwAAAAAACwAAAAAAAAASZWlwNzEyX2RvbWFpbl9uYW1lAAAAAAAQAAAAAAAAABVlaXA3MTJfZG9tYWluX3ZlcnNpb24AAAAAAAAQAAAAAA==",
        "AAAAAAAAAAAAAAAHZGVwb3NpdAAAAAADAAAAAAAAAARmcm9tAAAAEwAAAAAAAAAIY3VycmVuY3kAAAATAAAAAAAAAAZhbW91bnQAAAAAAAsAAAABAAAACw==",
        "AAAAAAAAAAAAAAAId2l0aGRyYXcAAAAGAAAAAAAAAARmcm9tAAAAEwAAAAAAAAANdGFyZ2V0X2Ftb3VudAAAAAAAAAsAAAAAAAAAA25hdgAAAAALAAAAAAAAAAxyZXF1ZXN0X2hhc2gAAAAOAAAAAAAAAAl0aW1lc3RhbXAAAAAAAAAGAAAAAAAAAAlzaWduYXR1cmUAAAAAAAAOAAAAAQAAAAs=",
        "AAAAAAAAAAAAAAARdHJlYXN1cmVyX2RlcG9zaXQAAAAAAAABAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAA",
        "AAAAAAAAAAAAAAAVYWRkX2N1cnJlbmN5X2J5X2FkbWluAAAAAAAAAQAAAAAAAAAIY3VycmVuY3kAAAATAAAAAA==",
        "AAAAAAAAAAAAAAAYcmVtb3ZlX2N1cnJlbmN5X2J5X2FkbWluAAAAAQAAAAAAAAAIY3VycmVuY3kAAAATAAAAAA==",
        "AAAAAAAAAAAAAAAec2V0X3dpdGhkcmF3X2N1cnJlbmN5X2J5X2FkbWluAAAAAAABAAAAAAAAAAhjdXJyZW5jeQAAABMAAAAA",
        "AAAAAAAAAAAAAAAYZ2V0X3N1cHBvcnRlZF9jdXJyZW5jaWVzAAAAAAAAAAEAAAPqAAAAEw==",
        "AAAAAAAAAAAAAAAVaXNfY3VycmVuY3lfc3VwcG9ydGVkAAAAAAAAAQAAAAAAAAAIY3VycmVuY3kAAAATAAAAAQAAAAE=",
        "AAAAAAAAAAAAAAAVZ2V0X3dpdGhkcmF3X2N1cnJlbmN5AAAAAAAAAAAAAAEAAAPoAAAAEw==",
        "AAAAAAAAAAAAAAAec2V0X3dpdGhkcmF3X3ZlcmlmaWVyX2J5X2FkbWluAAAAAAABAAAAAAAAABB2ZXJpZmllcl9hZGRyZXNzAAAAEwAAAAA=",
        "AAAAAAAAAAAAAAATc2V0X29yYWNsZV9ieV9hZG1pbgAAAAABAAAAAAAAAAZvcmFjbGUAAAAAABMAAAAA",
        "AAAAAAAAAAAAAAAWc2V0X3RyZWFzdXJlcl9ieV9hZG1pbgAAAAAAAQAAAAAAAAAJdHJlYXN1cmVyAAAAAAAAEwAAAAA=",
        "AAAAAAAAAAAAAAAbc2V0X21pbnRlcl9tYW5hZ2VyX2J5X2FkbWluAAAAAAEAAAAAAAAADm1pbnRlcl9tYW5hZ2VyAAAAAAATAAAAAA==",
        "AAAAAAAAAAAAAAAbc2V0X3dpdGhkcmF3X3JhdGlvX2J5X2FkbWluAAAAAAEAAAAAAAAADndpdGhkcmF3X3JhdGlvAAAAAAALAAAAAA==",
        "AAAAAAAAAAAAAAAac2V0X2VpcDcxMl9kb21haW5fYnlfYWRtaW4AAAAAAAIAAAAAAAAABG5hbWUAAAAQAAAAAAAAAAd2ZXJzaW9uAAAAABAAAAAA",
        "AAAAAAAAAAAAAAAFYWRtaW4AAAAAAAAAAAAAAQAAABM=",
        "AAAAAAAAAAAAAAAVZ2V0X3dpdGhkcmF3X3ZlcmlmaWVyAAAAAAAAAAAAAAEAAAAT",
        "AAAAAAAAAAAAAAAKZ2V0X29yYWNsZQAAAAAAAAAAAAEAAAAT",
        "AAAAAAAAAAAAAAANZ2V0X3RyZWFzdXJlcgAAAAAAAAAAAAABAAAAEw==",
        "AAAAAAAAAAAAAAASZ2V0X21pbnRlcl9tYW5hZ2VyAAAAAAAAAAAAAQAAABM=",
        "AAAAAAAAAAAAAAASZ2V0X3dpdGhkcmF3X3JhdGlvAAAAAAAAAAAAAQAAAAs=",
        "AAAAAAAAAAAAAAAOaXNfaW5pdGlhbGl6ZWQAAAAAAAAAAAABAAAAAQ==",
        "AAAAAAAAAAAAAAAWZ2V0X2VpcDcxMl9kb21haW5fbmFtZQAAAAAAAAAAAAEAAAAQ",
        "AAAAAAAAAAAAAAAZZ2V0X2VpcDcxMl9kb21haW5fdmVyc2lvbgAAAAAAAAAAAAABAAAAEA==",
        "AAAAAAAAAAAAAAATZ2V0X2VpcDcxMl9jaGFpbl9pZAAAAAAAAAAAAQAAAA4=",
        "AAAAAAAAAAAAAAAbZ2V0X2VpcDcxMl9kb21haW5fc2VwYXJhdG9yAAAAAAAAAAABAAAADg==" ]),
      options
    )
  }
  public readonly fromJSON = {
    initialize: this.txFromJSON<null>,
        deposit: this.txFromJSON<i128>,
        withdraw: this.txFromJSON<i128>,
        treasurer_deposit: this.txFromJSON<null>,
        add_currency_by_admin: this.txFromJSON<null>,
        remove_currency_by_admin: this.txFromJSON<null>,
        set_withdraw_currency_by_admin: this.txFromJSON<null>,
        get_supported_currencies: this.txFromJSON<Array<string>>,
        is_currency_supported: this.txFromJSON<boolean>,
        get_withdraw_currency: this.txFromJSON<Option<string>>,
        set_withdraw_verifier_by_admin: this.txFromJSON<null>,
        set_oracle_by_admin: this.txFromJSON<null>,
        set_treasurer_by_admin: this.txFromJSON<null>,
        set_minter_manager_by_admin: this.txFromJSON<null>,
        set_withdraw_ratio_by_admin: this.txFromJSON<null>,
        set_eip712_domain_by_admin: this.txFromJSON<null>,
        admin: this.txFromJSON<string>,
        get_withdraw_verifier: this.txFromJSON<string>,
        get_oracle: this.txFromJSON<string>,
        get_treasurer: this.txFromJSON<string>,
        get_minter_manager: this.txFromJSON<string>,
        get_withdraw_ratio: this.txFromJSON<i128>,
        is_initialized: this.txFromJSON<boolean>,
        get_eip712_domain_name: this.txFromJSON<string>,
        get_eip712_domain_version: this.txFromJSON<string>,
        get_eip712_chain_id: this.txFromJSON<Buffer>,
        get_eip712_domain_separator: this.txFromJSON<Buffer>
  }
}