/**
 * Derive a 256-bit AES key from PRF output using HKDF-SHA256.
 *
 * PRF output is high-entropy but not a proper key. HKDF extracts
 * and expands it into a cryptographically suitable encryption key.
 *
 * @param prfOutput - 32-byte PRF output from authenticator
 * @param salt - 32-byte random salt (unique per encryption)
 * @returns 32-byte derived AES-256 key
 */
export declare function deriveKey(prfOutput: Uint8Array, salt: Uint8Array): Uint8Array;
//# sourceMappingURL=kdf.d.ts.map