import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk';
export * as contract from '@stellar/stellar-sdk/contract';
export * as rpc from '@stellar/stellar-sdk/rpc';
if (typeof window !== 'undefined') {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
export const MinterManagerError = {
    1: { message: "Unauthorized" },
    2: { message: "InvalidArgument" },
    3: { message: "TooManyMinters" },
    4: { message: "MinterNotFound" },
    5: { message: "MinterAlreadyExists" },
    6: { message: "NotInitialized" },
    7: { message: "AlreadyInitialized" }
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy(null, options);
    }
    constructor(options) {
        super(new ContractSpec(["AAAABAAAAAAAAAAAAAAAEk1pbnRlck1hbmFnZXJFcnJvcgAAAAAABwAAAAAAAAAMVW5hdXRob3JpemVkAAAAAQAAAAAAAAAPSW52YWxpZEFyZ3VtZW50AAAAAAIAAAAAAAAADlRvb01hbnlNaW50ZXJzAAAAAAADAAAAAAAAAA5NaW50ZXJOb3RGb3VuZAAAAAAABAAAAAAAAAATTWludGVyQWxyZWFkeUV4aXN0cwAAAAAFAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAABgAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAAH",
            "AAAAAgAAAAAAAAAAAAAAB0RhdGFLZXkAAAAABAAAAAAAAAAAAAAABUFkbWluAAAAAAAAAAAAAAAAAAALSW5pdGlhbGl6ZWQAAAAAAAAAAAAAAAAHTWludGVycwAAAAAAAAAAAAAAAA1Ub2tlbkNvbnRyYWN0AAAA",
            "AAAAAAAAAAAAAAAKaW5pdGlhbGl6ZQAAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAA50b2tlbl9jb250cmFjdAAAAAAAEwAAAAA=",
            "AAAAAAAAAAAAAAAOaXNfaW5pdGlhbGl6ZWQAAAAAAAAAAAABAAAAAQ==",
            "AAAAAAAAAAAAAAAFYWRtaW4AAAAAAAAAAAAAAQAAABM=",
            "AAAAAAAAAAAAAAAOdHJhbnNmZXJfYWRtaW4AAAAAAAEAAAAAAAAACW5ld19hZG1pbgAAAAAAABMAAAAA",
            "AAAAAAAAAAAAAAATYWRkX21pbnRlcl9ieV9hZG1pbgAAAAABAAAAAAAAAAZtaW50ZXIAAAAAABMAAAAA",
            "AAAAAAAAAAAAAAAWcmVtb3ZlX21pbnRlcl9ieV9hZG1pbgAAAAAAAQAAAAAAAAAGbWludGVyAAAAAAATAAAAAA==",
            "AAAAAAAAAAAAAAALZ2V0X21pbnRlcnMAAAAAAAAAAAEAAAPqAAAAEw==",
            "AAAAAAAAAAAAAAAJaXNfbWludGVyAAAAAAAAAQAAAAAAAAAHYWRkcmVzcwAAAAATAAAAAQAAAAE=",
            "AAAAAAAAAAAAAAAEbWludAAAAAQAAAAAAAAABGZyb20AAAATAAAAAAAAAA50b2tlbl9jb250cmFjdAAAAAAAEwAAAAAAAAACdG8AAAAAABMAAAAAAAAABmFtb3VudAAAAAAACwAAAAA=",
            "AAAAAAAAAAAAAAAEYnVybgAAAAMAAAAAAAAABGZyb20AAAATAAAAAAAAAA50b2tlbl9jb250cmFjdAAAAAAAEwAAAAAAAAAGYW1vdW50AAAAAAALAAAAAA==",
            "AAAAAAAAAAAAAAAOdG9rZW5fY29udHJhY3QAAAAAAAAAAAABAAAAEw==",
            "AAAAAQAAAAAAAAAAAAAAE0Z1bmdpYmxlVG9rZW5DbGllbnQAAAAAAQAAAAAAAAALY29udHJhY3RfaWQAAAAAEw=="]), options);
        this.options = options;
    }
    fromJSON = {
        initialize: (this.txFromJSON),
        is_initialized: (this.txFromJSON),
        admin: (this.txFromJSON),
        transfer_admin: (this.txFromJSON),
        add_minter_by_admin: (this.txFromJSON),
        remove_minter_by_admin: (this.txFromJSON),
        get_minters: (this.txFromJSON),
        is_minter: (this.txFromJSON),
        mint: (this.txFromJSON),
        burn: (this.txFromJSON),
        token_contract: (this.txFromJSON)
    };
}
