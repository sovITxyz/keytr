export declare class KeytrError extends Error {
    constructor(message: string);
}
export declare class EncryptionError extends KeytrError {
    constructor(message: string);
}
export declare class DecryptionError extends KeytrError {
    constructor(message: string);
}
export declare class BlobParseError extends KeytrError {
    constructor(message: string);
}
export declare class WebAuthnError extends KeytrError {
    constructor(message: string);
}
export declare class RelayError extends KeytrError {
    constructor(message: string);
}
//# sourceMappingURL=errors.d.ts.map