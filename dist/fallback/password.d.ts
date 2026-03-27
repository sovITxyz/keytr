interface ScryptParams {
    N: number;
    r: number;
    p: number;
}
/** Encrypt nsec with a password using scrypt + AES-256-GCM */
export declare function encryptNsecWithPassword(nsecBytes: Uint8Array, password: string, scryptParams?: ScryptParams): string;
/** Decrypt nsec from a password-encrypted blob */
export declare function decryptNsecFromPassword(encryptedBlob: string, password: string, scryptParams?: ScryptParams): Uint8Array;
export {};
//# sourceMappingURL=password.d.ts.map