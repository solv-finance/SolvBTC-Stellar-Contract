import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk';
export * as contract from '@stellar/stellar-sdk/contract';
export * as rpc from '@stellar/stellar-sdk/rpc';
if (typeof window !== 'undefined') {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
export const TokenError = {
    1: { message: "Unauthorized" },
    2: { message: "Paused" },
    3: { message: "InsufficientBalance" },
    4: { message: "InvalidArgument" },
    5: { message: "AlreadyInitialized" },
    6: { message: "NotInitialized" },
    7: { message: "InvalidAddress" },
    8: { message: "InvalidAmount" },
    9: { message: "AddressBlacklisted" }
};
export const FungibleTokenError = {
    /**
     * Indicates an error related to the current balance of account from which
     * tokens are expected to be transferred.
     */
    200: { message: "InsufficientBalance" },
    /**
     * Indicates a failure with the allowance mechanism when a given spender
     * doesn't have enough allowance.
     */
    201: { message: "InsufficientAllowance" },
    /**
     * Indicates an invalid value for `live_until_ledger` when setting an
     * allowance.
     */
    202: { message: "InvalidLiveUntilLedger" },
    /**
     * Indicates an error when an input that must be >= 0
     */
    203: { message: "LessThanZero" },
    /**
     * Indicates overflow when adding two values
     */
    204: { message: "MathOverflow" },
    /**
     * Indicates access to uninitialized metadata
     */
    205: { message: "UnsetMetadata" },
    /**
     * Indicates that the operation would have caused `total_supply` to exceed
     * the `cap`.
     */
    206: { message: "ExceededCap" },
    /**
     * Indicates the supplied `cap` is not a valid cap value.
     */
    207: { message: "InvalidCap" },
    /**
     * Indicates the Cap was not set.
     */
    208: { message: "CapNotSet" }
};
export const PausableError = {
    /**
     * The operation failed because the contract is paused.
     */
    100: { message: "EnforcedPause" },
    /**
     * The operation failed because the contract is not paused.
     */
    101: { message: "ExpectedPause" }
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy(null, options);
    }
    constructor(options) {
        super(new ContractSpec(["AAAAAgAAAAAAAAAAAAAAB0RhdGFLZXkAAAAABAAAAAAAAAAAAAAACE1ldGFkYXRhAAAAAAAAAAAAAAAFQWRtaW4AAAAAAAAAAAAAAAAAAAtJbml0aWFsaXplZAAAAAAAAAAAAAAAABFNaW50QXV0aG9yaXphdGlvbgAAAA==",
            "AAAAAgAAAAAAAAAAAAAAEEJsYWNrbGlzdERhdGFLZXkAAAABAAAAAQAAAAAAAAAQQmxhY2tMaXN0QWRkcmVzcwAAAAEAAAAT",
            "AAAAAQAAAAAAAAAAAAAADVRva2VuTWV0YWRhdGEAAAAAAAADAAAAAAAAAAhkZWNpbWFscwAAAAQAAAAAAAAABG5hbWUAAAAQAAAAAAAAAAZzeW1ib2wAAAAAABA=",
            "AAAABAAAAAAAAAAAAAAAClRva2VuRXJyb3IAAAAAAAkAAAAAAAAADFVuYXV0aG9yaXplZAAAAAEAAAAAAAAABlBhdXNlZAAAAAAAAgAAAAAAAAATSW5zdWZmaWNpZW50QmFsYW5jZQAAAAADAAAAAAAAAA9JbnZhbGlkQXJndW1lbnQAAAAABAAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAAFAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAABgAAAAAAAAAOSW52YWxpZEFkZHJlc3MAAAAAAAcAAAAAAAAADUludmFsaWRBbW91bnQAAAAAAAAIAAAAAAAAABJBZGRyZXNzQmxhY2tsaXN0ZWQAAAAAAAk=",
            "AAAAAAAAAAAAAAAKaW5pdGlhbGl6ZQAAAAAABQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAARuYW1lAAAAEAAAAAAAAAAGc3ltYm9sAAAAAAAQAAAAAAAAAAhkZWNpbWFscwAAAAQAAAAAAAAAEm1pbnRfYXV0aG9yaXphdGlvbgAAAAAAEwAAAAA=",
            "AAAAAAAAAAAAAAAEbmFtZQAAAAAAAAABAAAAEA==",
            "AAAAAAAAAAAAAAAGc3ltYm9sAAAAAAAAAAAAAQAAABA=",
            "AAAAAAAAAAAAAAAIZGVjaW1hbHMAAAAAAAAAAQAAAAQ=",
            "AAAAAAAAAAAAAAAMdG90YWxfc3VwcGx5AAAAAAAAAAEAAAAL",
            "AAAAAAAAAAAAAAAKYmFsYW5jZV9vZgAAAAAAAQAAAAAAAAAHYWNjb3VudAAAAAATAAAAAQAAAAs=",
            "AAAAAAAAAAAAAAAIdHJhbnNmZXIAAAADAAAAAAAAAARmcm9tAAAAEwAAAAAAAAACdG8AAAAAABMAAAAAAAAABmFtb3VudAAAAAAACwAAAAA=",
            "AAAAAAAAAAAAAAAHYXBwcm92ZQAAAAADAAAAAAAAAARmcm9tAAAAEwAAAAAAAAAHc3BlbmRlcgAAAAATAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAA",
            "AAAAAAAAAAAAAAAJYWxsb3dhbmNlAAAAAAAAAgAAAAAAAAAEZnJvbQAAABMAAAAAAAAAB3NwZW5kZXIAAAAAEwAAAAEAAAAL",
            "AAAAAAAAAAAAAAANdHJhbnNmZXJfZnJvbQAAAAAAAAQAAAAAAAAAB3NwZW5kZXIAAAAAEwAAAAAAAAAEZnJvbQAAABMAAAAAAAAAAnRvAAAAAAATAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAA",
            "AAAAAAAAAAAAAAAOaXNfaW5pdGlhbGl6ZWQAAAAAAAAAAAABAAAAAQ==",
            "AAAAAAAAAAAAAAAEbWludAAAAAIAAAAAAAAAAnRvAAAAAAATAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAA",
            "AAAAAAAAAAAAAAAEYnVybgAAAAEAAAAAAAAABmFtb3VudAAAAAAACwAAAAA=",
            "AAAAAAAAAAAAAAAFcGF1c2UAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAHdW5wYXVzZQAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAJaXNfcGF1c2VkAAAAAAAAAAAAAAEAAAAB",
            "AAAAAAAAAAAAAAAQYWRkX3RvX2JsYWNrbGlzdAAAAAEAAAAAAAAAB2FkZHJlc3MAAAAAEwAAAAA=",
            "AAAAAAAAAAAAAAAVcmVtb3ZlX2Zyb21fYmxhY2tsaXN0AAAAAAAAAQAAAAAAAAAHYWRkcmVzcwAAAAATAAAAAA==",
            "AAAAAAAAAAAAAAAOaXNfYmxhY2tsaXN0ZWQAAAAAAAEAAAAAAAAAB2FkZHJlc3MAAAAAEwAAAAEAAAAB",
            "AAAAAAAAAAAAAAAFYWRtaW4AAAAAAAAAAAAAAQAAA+gAAAAT",
            "AAAAAAAAAAAAAAAOdHJhbnNmZXJfYWRtaW4AAAAAAAEAAAAAAAAACW5ld19hZG1pbgAAAAAAABMAAAAA",
            "AAAAAAAAAAAAAAAbdHJhbnNmZXJfbWludF9hdXRob3JpemF0aW9uAAAAAAEAAAAAAAAAFm5ld19taW50X2F1dGhvcml6YXRpb24AAAAAABMAAAAA",
            "AAAAAAAAAAAAAAASbWludF9hdXRob3JpemF0aW9uAAAAAAAAAAAAAQAAA+gAAAAT",
            "AAAAAQAAACRTdG9yYWdlIGNvbnRhaW5lciBmb3IgdG9rZW4gbWV0YWRhdGEAAAAAAAAACE1ldGFkYXRhAAAAAwAAAAAAAAAIZGVjaW1hbHMAAAAEAAAAAAAAAARuYW1lAAAAEAAAAAAAAAAGc3ltYm9sAAAAAAAQ",
            "AAAABAAAAAAAAAAAAAAAEkZ1bmdpYmxlVG9rZW5FcnJvcgAAAAAACQAAAG5JbmRpY2F0ZXMgYW4gZXJyb3IgcmVsYXRlZCB0byB0aGUgY3VycmVudCBiYWxhbmNlIG9mIGFjY291bnQgZnJvbSB3aGljaAp0b2tlbnMgYXJlIGV4cGVjdGVkIHRvIGJlIHRyYW5zZmVycmVkLgAAAAAAE0luc3VmZmljaWVudEJhbGFuY2UAAAAAyAAAAGRJbmRpY2F0ZXMgYSBmYWlsdXJlIHdpdGggdGhlIGFsbG93YW5jZSBtZWNoYW5pc20gd2hlbiBhIGdpdmVuIHNwZW5kZXIKZG9lc24ndCBoYXZlIGVub3VnaCBhbGxvd2FuY2UuAAAAFUluc3VmZmljaWVudEFsbG93YW5jZQAAAAAAAMkAAABNSW5kaWNhdGVzIGFuIGludmFsaWQgdmFsdWUgZm9yIGBsaXZlX3VudGlsX2xlZGdlcmAgd2hlbiBzZXR0aW5nIGFuCmFsbG93YW5jZS4AAAAAAAAWSW52YWxpZExpdmVVbnRpbExlZGdlcgAAAAAAygAAADJJbmRpY2F0ZXMgYW4gZXJyb3Igd2hlbiBhbiBpbnB1dCB0aGF0IG11c3QgYmUgPj0gMAAAAAAADExlc3NUaGFuWmVybwAAAMsAAAApSW5kaWNhdGVzIG92ZXJmbG93IHdoZW4gYWRkaW5nIHR3byB2YWx1ZXMAAAAAAAAMTWF0aE92ZXJmbG93AAAAzAAAACpJbmRpY2F0ZXMgYWNjZXNzIHRvIHVuaW5pdGlhbGl6ZWQgbWV0YWRhdGEAAAAAAA1VbnNldE1ldGFkYXRhAAAAAAAAzQAAAFJJbmRpY2F0ZXMgdGhhdCB0aGUgb3BlcmF0aW9uIHdvdWxkIGhhdmUgY2F1c2VkIGB0b3RhbF9zdXBwbHlgIHRvIGV4Y2VlZAp0aGUgYGNhcGAuAAAAAAALRXhjZWVkZWRDYXAAAAAAzgAAADZJbmRpY2F0ZXMgdGhlIHN1cHBsaWVkIGBjYXBgIGlzIG5vdCBhIHZhbGlkIGNhcCB2YWx1ZS4AAAAAAApJbnZhbGlkQ2FwAAAAAADPAAAAHkluZGljYXRlcyB0aGUgQ2FwIHdhcyBub3Qgc2V0LgAAAAAACUNhcE5vdFNldAAAAAAAANA=",
            "AAAAAQAAACpTdG9yYWdlIGtleSB0aGF0IG1hcHMgdG8gW2BBbGxvd2FuY2VEYXRhYF0AAAAAAAAAAAAMQWxsb3dhbmNlS2V5AAAAAgAAAAAAAAAFb3duZXIAAAAAAAATAAAAAAAAAAdzcGVuZGVyAAAAABM=",
            "AAAAAQAAAINTdG9yYWdlIGNvbnRhaW5lciBmb3IgdGhlIGFtb3VudCBvZiB0b2tlbnMgZm9yIHdoaWNoIGFuIGFsbG93YW5jZSBpcyBncmFudGVkCmFuZCB0aGUgbGVkZ2VyIG51bWJlciBhdCB3aGljaCB0aGlzIGFsbG93YW5jZSBleHBpcmVzLgAAAAAAAAAADUFsbG93YW5jZURhdGEAAAAAAAACAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAAEWxpdmVfdW50aWxfbGVkZ2VyAAAAAAAABA==",
            "AAAAAgAAADlTdG9yYWdlIGtleXMgZm9yIHRoZSBkYXRhIGFzc29jaWF0ZWQgd2l0aCBgRnVuZ2libGVUb2tlbmAAAAAAAAAAAAAAClN0b3JhZ2VLZXkAAAAAAAMAAAAAAAAAAAAAAAtUb3RhbFN1cHBseQAAAAABAAAAAAAAAAdCYWxhbmNlAAAAAAEAAAATAAAAAQAAAAAAAAAJQWxsb3dhbmNlAAAAAAAAAQAAB9AAAAAMQWxsb3dhbmNlS2V5",
            "AAAABAAAAAAAAAAAAAAADVBhdXNhYmxlRXJyb3IAAAAAAAACAAAANFRoZSBvcGVyYXRpb24gZmFpbGVkIGJlY2F1c2UgdGhlIGNvbnRyYWN0IGlzIHBhdXNlZC4AAAANRW5mb3JjZWRQYXVzZQAAAAAAAGQAAAA4VGhlIG9wZXJhdGlvbiBmYWlsZWQgYmVjYXVzZSB0aGUgY29udHJhY3QgaXMgbm90IHBhdXNlZC4AAAANRXhwZWN0ZWRQYXVzZQAAAAAAAGU="]), options);
        this.options = options;
    }
    fromJSON = {
        initialize: (this.txFromJSON),
        name: (this.txFromJSON),
        symbol: (this.txFromJSON),
        decimals: (this.txFromJSON),
        total_supply: (this.txFromJSON),
        balance_of: (this.txFromJSON),
        transfer: (this.txFromJSON),
        approve: (this.txFromJSON),
        allowance: (this.txFromJSON),
        transfer_from: (this.txFromJSON),
        is_initialized: (this.txFromJSON),
        mint: (this.txFromJSON),
        burn: (this.txFromJSON),
        pause: (this.txFromJSON),
        unpause: (this.txFromJSON),
        is_paused: (this.txFromJSON),
        add_to_blacklist: (this.txFromJSON),
        remove_from_blacklist: (this.txFromJSON),
        is_blacklisted: (this.txFromJSON),
        admin: (this.txFromJSON),
        transfer_admin: (this.txFromJSON),
        transfer_mint_authorization: (this.txFromJSON),
        mint_authorization: (this.txFromJSON)
    };
}
