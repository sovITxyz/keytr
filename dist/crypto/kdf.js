import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { HKDF_INFO } from '../types.js';
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
export function deriveKey(prfOutput, salt) {
    if (prfOutput.length !== 32) {
        throw new Error(`PRF output must be 32 bytes, got ${prfOutput.length}`);
    }
    if (salt.length !== 32) {
        throw new Error(`Salt must be 32 bytes, got ${salt.length}`);
    }
    const info = new TextEncoder().encode(HKDF_INFO);
    return hkdf(sha256, prfOutput, salt, info, 32);
}
//# sourceMappingURL=kdf.js.map