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




export const OracleError = {
  1: {message:"Unauthorized"},
  2: {message:"InvalidArgument"},
  3: {message:"NotInitialized"},
  4: {message:"AlreadyInitialized"},
  5: {message:"NavChangeExceedsLimit"},
  6: {message:"NavManagerNotSet"}
}

export type DataKey = {tag: "Admin", values: void} | {tag: "Initialized", values: void} | {tag: "Nav", values: void} | {tag: "NavDecimals", values: void} | {tag: "NavManager", values: void} | {tag: "MaxNavChangePercent", values: void};

export interface Client {
  /**
   * Construct and simulate a initialize transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Initialize contract
   */
  initialize: ({admin, nav_decimals, initial_nav, max_change_percent}: {admin: string, nav_decimals: u32, initial_nav: i128, max_change_percent: u32}, options?: {
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
   * Construct and simulate a is_initialized transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Check if contract is initialized
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
   * Construct and simulate a get_nav transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Get current NAV value
   */
  get_nav: (options?: {
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
   * Construct and simulate a get_nav_decimals transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Get NAV decimal places
   */
  get_nav_decimals: (options?: {
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
  }) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a max_nav_change_percent transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Get maximum NAV change percentage
   */
  max_nav_change_percent: (options?: {
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
  }) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Get admin address
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
   * Construct and simulate a set_nav_manager_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Set NAV manager (admin only)
   */
  set_nav_manager_by_admin: ({manager_address}: {manager_address: string}, options?: {
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
   * Construct and simulate a set_max_nav_change_by_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Set maximum NAV change percentage (admin only)
   */
  set_max_nav_change_by_admin: ({max_change_percent}: {max_change_percent: u32}, options?: {
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
   * Construct and simulate a nav_manager transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Get NAV manager address
   */
  nav_manager: (options?: {
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
   * Construct and simulate a set_nav_by_manager transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Set NAV value (NAV manager only)
   */
  set_nav_by_manager: ({nav}: {nav: i128}, options?: {
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
   * Construct and simulate a emit_initialization_event transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Publish initialization event
   */
  emit_initialization_event: ({admin, initial_nav, nav_decimals, max_change_percent}: {admin: string, initial_nav: i128, nav_decimals: u32, max_change_percent: u32}, options?: {
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
   * Construct and simulate a emit_nav_manager_set_event transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Publish NAV manager set event
   */
  emit_nav_manager_set_event: ({admin, nav_manager}: {admin: string, nav_manager: string}, options?: {
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
   * Construct and simulate a emit_max_change_updated_event transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Publish maximum change percentage update event
   */
  emit_max_change_updated_event: ({admin, max_change_percent}: {admin: string, max_change_percent: u32}, options?: {
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
   * Construct and simulate a emit_nav_updated_event transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Publish NAV value update event
   */
  emit_nav_updated_event: ({nav_manager, old_nav, new_nav}: {nav_manager: string, old_nav: i128, new_nav: i128}, options?: {
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
      new ContractSpec([ "AAAABAAAAAAAAAAAAAAAC09yYWNsZUVycm9yAAAAAAYAAAAAAAAADFVuYXV0aG9yaXplZAAAAAEAAAAAAAAAD0ludmFsaWRBcmd1bWVudAAAAAACAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAwAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAAEAAAAAAAAABVOYXZDaGFuZ2VFeGNlZWRzTGltaXQAAAAAAAAFAAAAAAAAABBOYXZNYW5hZ2VyTm90U2V0AAAABg==",
        "AAAAAgAAAAAAAAAAAAAAB0RhdGFLZXkAAAAABgAAAAAAAAAAAAAABUFkbWluAAAAAAAAAAAAAAAAAAALSW5pdGlhbGl6ZWQAAAAAAAAAAAAAAAADTmF2AAAAAAAAAAAAAAAAC05hdkRlY2ltYWxzAAAAAAAAAAAAAAAACk5hdk1hbmFnZXIAAAAAAAAAAAAAAAAAE01heE5hdkNoYW5nZVBlcmNlbnQA",
        "AAAAAAAAABNJbml0aWFsaXplIGNvbnRyYWN0AAAAAAppbml0aWFsaXplAAAAAAAEAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAADG5hdl9kZWNpbWFscwAAAAQAAAAAAAAAC2luaXRpYWxfbmF2AAAAAAsAAAAAAAAAEm1heF9jaGFuZ2VfcGVyY2VudAAAAAAABAAAAAA=",
        "AAAAAAAAACBDaGVjayBpZiBjb250cmFjdCBpcyBpbml0aWFsaXplZAAAAA5pc19pbml0aWFsaXplZAAAAAAAAAAAAAEAAAAB",
        "AAAAAAAAABVHZXQgY3VycmVudCBOQVYgdmFsdWUAAAAAAAAHZ2V0X25hdgAAAAAAAAAAAQAAAAs=",
        "AAAAAAAAABZHZXQgTkFWIGRlY2ltYWwgcGxhY2VzAAAAAAAQZ2V0X25hdl9kZWNpbWFscwAAAAAAAAABAAAABA==",
        "AAAAAAAAACFHZXQgbWF4aW11bSBOQVYgY2hhbmdlIHBlcmNlbnRhZ2UAAAAAAAAWbWF4X25hdl9jaGFuZ2VfcGVyY2VudAAAAAAAAAAAAAEAAAAE",
        "AAAAAAAAABFHZXQgYWRtaW4gYWRkcmVzcwAAAAAAAAVhZG1pbgAAAAAAAAAAAAABAAAAEw==",
        "AAAAAAAAABxTZXQgTkFWIG1hbmFnZXIgKGFkbWluIG9ubHkpAAAAGHNldF9uYXZfbWFuYWdlcl9ieV9hZG1pbgAAAAEAAAAAAAAAD21hbmFnZXJfYWRkcmVzcwAAAAATAAAAAA==",
        "AAAAAAAAAC5TZXQgbWF4aW11bSBOQVYgY2hhbmdlIHBlcmNlbnRhZ2UgKGFkbWluIG9ubHkpAAAAAAAbc2V0X21heF9uYXZfY2hhbmdlX2J5X2FkbWluAAAAAAEAAAAAAAAAEm1heF9jaGFuZ2VfcGVyY2VudAAAAAAABAAAAAA=",
        "AAAAAAAAABdHZXQgTkFWIG1hbmFnZXIgYWRkcmVzcwAAAAALbmF2X21hbmFnZXIAAAAAAAAAAAEAAAPoAAAAEw==",
        "AAAAAAAAACBTZXQgTkFWIHZhbHVlIChOQVYgbWFuYWdlciBvbmx5KQAAABJzZXRfbmF2X2J5X21hbmFnZXIAAAAAAAEAAAAAAAAAA25hdgAAAAALAAAAAA==",
        "AAAAAAAAABxQdWJsaXNoIGluaXRpYWxpemF0aW9uIGV2ZW50AAAAGWVtaXRfaW5pdGlhbGl6YXRpb25fZXZlbnQAAAAAAAAEAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAC2luaXRpYWxfbmF2AAAAAAsAAAAAAAAADG5hdl9kZWNpbWFscwAAAAQAAAAAAAAAEm1heF9jaGFuZ2VfcGVyY2VudAAAAAAABAAAAAA=",
        "AAAAAAAAAB1QdWJsaXNoIE5BViBtYW5hZ2VyIHNldCBldmVudAAAAAAAABplbWl0X25hdl9tYW5hZ2VyX3NldF9ldmVudAAAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAtuYXZfbWFuYWdlcgAAAAATAAAAAA==",
        "AAAAAAAAAC5QdWJsaXNoIG1heGltdW0gY2hhbmdlIHBlcmNlbnRhZ2UgdXBkYXRlIGV2ZW50AAAAAAAdZW1pdF9tYXhfY2hhbmdlX3VwZGF0ZWRfZXZlbnQAAAAAAAACAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAEm1heF9jaGFuZ2VfcGVyY2VudAAAAAAABAAAAAA=",
        "AAAAAAAAAB5QdWJsaXNoIE5BViB2YWx1ZSB1cGRhdGUgZXZlbnQAAAAAABZlbWl0X25hdl91cGRhdGVkX2V2ZW50AAAAAAADAAAAAAAAAAtuYXZfbWFuYWdlcgAAAAATAAAAAAAAAAdvbGRfbmF2AAAAAAsAAAAAAAAAB25ld19uYXYAAAAACwAAAAA=" ]),
      options
    )
  }
  public readonly fromJSON = {
    initialize: this.txFromJSON<null>,
        is_initialized: this.txFromJSON<boolean>,
        get_nav: this.txFromJSON<i128>,
        get_nav_decimals: this.txFromJSON<u32>,
        max_nav_change_percent: this.txFromJSON<u32>,
        admin: this.txFromJSON<string>,
        set_nav_manager_by_admin: this.txFromJSON<null>,
        set_max_nav_change_by_admin: this.txFromJSON<null>,
        nav_manager: this.txFromJSON<Option<string>>,
        set_nav_by_manager: this.txFromJSON<null>,
        emit_initialization_event: this.txFromJSON<null>,
        emit_nav_manager_set_event: this.txFromJSON<null>,
        emit_max_change_updated_event: this.txFromJSON<null>,
        emit_nav_updated_event: this.txFromJSON<null>
  }
}