import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk';
export * as contract from '@stellar/stellar-sdk/contract';
export * as rpc from '@stellar/stellar-sdk/rpc';
if (typeof window !== 'undefined') {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
export const OracleError = {
    1: { message: "Unauthorized" },
    2: { message: "InvalidArgument" },
    3: { message: "NotInitialized" },
    4: { message: "AlreadyInitialized" },
    5: { message: "NavChangeExceedsLimit" },
    6: { message: "NavManagerNotSet" }
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy(null, options);
    }
    constructor(options) {
        super(new ContractSpec(["AAAABAAAAAAAAAAAAAAAC09yYWNsZUVycm9yAAAAAAYAAAAAAAAADFVuYXV0aG9yaXplZAAAAAEAAAAAAAAAD0ludmFsaWRBcmd1bWVudAAAAAACAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAwAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAAEAAAAAAAAABVOYXZDaGFuZ2VFeGNlZWRzTGltaXQAAAAAAAAFAAAAAAAAABBOYXZNYW5hZ2VyTm90U2V0AAAABg==",
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
            "AAAAAAAAAB5QdWJsaXNoIE5BViB2YWx1ZSB1cGRhdGUgZXZlbnQAAAAAABZlbWl0X25hdl91cGRhdGVkX2V2ZW50AAAAAAADAAAAAAAAAAtuYXZfbWFuYWdlcgAAAAATAAAAAAAAAAdvbGRfbmF2AAAAAAsAAAAAAAAAB25ld19uYXYAAAAACwAAAAA="]), options);
        this.options = options;
    }
    fromJSON = {
        initialize: (this.txFromJSON),
        is_initialized: (this.txFromJSON),
        get_nav: (this.txFromJSON),
        get_nav_decimals: (this.txFromJSON),
        max_nav_change_percent: (this.txFromJSON),
        admin: (this.txFromJSON),
        set_nav_manager_by_admin: (this.txFromJSON),
        set_max_nav_change_by_admin: (this.txFromJSON),
        nav_manager: (this.txFromJSON),
        set_nav_by_manager: (this.txFromJSON),
        emit_initialization_event: (this.txFromJSON),
        emit_nav_manager_set_event: (this.txFromJSON),
        emit_max_change_updated_event: (this.txFromJSON),
        emit_nav_updated_event: (this.txFromJSON)
    };
}
