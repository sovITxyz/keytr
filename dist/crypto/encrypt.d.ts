import { type EncryptOptions } from '../types.js';
/**
 * Build the Additional Authenticated Data (AAD) for AES-GCM.
 * AAD = "keytr" || version_byte || credentialId
 */
export declare function buildAad(credentialId: Uint8Array, version?: number): Uint8Array;
/**
 * Encrypt a 32-byte nsec using a key derived from the passkey's embedded key.
 *
 * @returns Base64-encoded encrypted blob (93 bytes binary -> ~124 chars)
 */
export declare function encryptNsec(options: EncryptOptions): string;
//# sourceMappingURL=encrypt.d.ts.map