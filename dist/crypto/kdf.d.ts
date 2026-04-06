/**
 * Derive a 256-bit AES key from key material using HKDF-SHA256.
 *
 * The key material (from the passkey's user.id) is high-entropy but
 * not a proper key. HKDF extracts and expands it into a
 * cryptographically suitable encryption key.
 *
 * @param keyMaterial - 32-byte key from userHandle
 * @param salt - 32-byte random salt (unique per encryption)
 * @returns 32-byte derived AES-256 key
 */
export declare function deriveKey(keyMaterial: Uint8Array, salt: Uint8Array): Uint8Array;
//# sourceMappingURL=kdf.d.ts.map