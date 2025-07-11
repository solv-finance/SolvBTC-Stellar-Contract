import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk';
export * as contract from '@stellar/stellar-sdk/contract';
export * as rpc from '@stellar/stellar-sdk/rpc';
if (typeof window !== 'undefined') {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
/**
 * Error code definition
 */
export const VaultError = {
    /**
     * Permission insufficient
     */
    1: { message: "Unauthorized" },
    /**
     * Invalid parameter
     */
    2: { message: "InvalidArgument" },
    /**
     * Contract not initialized
     */
    3: { message: "NotInitialized" },
    /**
     * Contract already initialized
     */
    4: { message: "AlreadyInitialized" },
    /**
     * Currency not supported
     */
    5: { message: "CurrencyNotSupported" },
    /**
     * Exceeds maximum currency quantity
     */
    6: { message: "TooManyCurrencies" },
    /**
     * Currency already exists
     */
    7: { message: "CurrencyAlreadyExists" },
    /**
     * Currency does not exist
     */
    8: { message: "CurrencyNotExists" },
    /**
     * Invalid amount
     */
    9: { message: "InvalidAmount" },
    /**
     * Oracle not set
     */
    10: { message: "OracleNotSet" },
    /**
     * Minter Manager not set
     */
    11: { message: "MinterManagerNotSet" },
    /**
     * Treasurer not set
     */
    12: { message: "TreasurerNotSet" },
    /**
     * Withdrawal verifier not set
     */
    13: { message: "WithdrawVerifierNotSet" },
    /**
     * Withdrawal currency not set
     */
    14: { message: "WithdrawCurrencyNotSet" },
    /**
     * Signature verification failed
     */
    15: { message: "InvalidSignature" },
    /**
     * Request hash already used
     */
    16: { message: "RequestHashAlreadyUsed" },
    /**
     * Invalid NAV
     */
    17: { message: "InvalidNav" },
    /**
     * Invalid withdraw fee ratio
     */
    18: { message: "InvalidWithdrawRatio" },
    /**
     * Fee collector address not set
     */
    19: { message: "FeeCollectorNotSet" },
    /**
     * NAV value expired
     */
    20: { message: "StaleNavValue" },
    /**
     * Invalid fee amount
     */
    21: { message: "InvalidFeeAmount" },
    /**
     * Token contract not set
     */
    22: { message: "TokenContractNotSet" },
    /**
     * Invalid signature format
     */
    23: { message: "InvalidSignatureFormat" }
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy(null, options);
    }
    constructor(options) {
        super(new ContractSpec(["AAAAAQAAADNFSVA3MTIgc2lnbmF0dXJlIGRhdGEgc3RydWN0dXJlOiB3aXRoZHJhd2FsIHJlcXVlc3QAAAAAAAAAAA9XaXRoZHJhd1JlcXVlc3QAAAAABgAAAAAAAAADbmF2AAAAAAsAAAAAAAAADHJlcXVlc3RfaGFzaAAAAA4AAAAAAAAACXNpZ25hdHVyZQAAAAAAAA4AAAAAAAAADXRhcmdldF9hbW91bnQAAAAAAAALAAAAAAAAAAl0aW1lc3RhbXAAAAAAAAAGAAAAAAAAAAR1c2VyAAAAEw==",
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
            "AAAAAAAAAAAAAAAbZ2V0X2VpcDcxMl9kb21haW5fc2VwYXJhdG9yAAAAAAAAAAABAAAADg=="]), options);
        this.options = options;
    }
    fromJSON = {
        initialize: (this.txFromJSON),
        deposit: (this.txFromJSON),
        withdraw: (this.txFromJSON),
        treasurer_deposit: (this.txFromJSON),
        add_currency_by_admin: (this.txFromJSON),
        remove_currency_by_admin: (this.txFromJSON),
        set_withdraw_currency_by_admin: (this.txFromJSON),
        get_supported_currencies: (this.txFromJSON),
        is_currency_supported: (this.txFromJSON),
        get_withdraw_currency: (this.txFromJSON),
        set_withdraw_verifier_by_admin: (this.txFromJSON),
        set_oracle_by_admin: (this.txFromJSON),
        set_treasurer_by_admin: (this.txFromJSON),
        set_minter_manager_by_admin: (this.txFromJSON),
        set_withdraw_ratio_by_admin: (this.txFromJSON),
        set_eip712_domain_by_admin: (this.txFromJSON),
        admin: (this.txFromJSON),
        get_withdraw_verifier: (this.txFromJSON),
        get_oracle: (this.txFromJSON),
        get_treasurer: (this.txFromJSON),
        get_minter_manager: (this.txFromJSON),
        get_withdraw_ratio: (this.txFromJSON),
        is_initialized: (this.txFromJSON),
        get_eip712_domain_name: (this.txFromJSON),
        get_eip712_domain_version: (this.txFromJSON),
        get_eip712_chain_id: (this.txFromJSON),
        get_eip712_domain_separator: (this.txFromJSON)
    };
}
