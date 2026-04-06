import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { HKDF_INFO } from '../types.js';
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
export function deriveKey(keyMaterial, salt) {
    if (keyMaterial.length !== 32) {
        throw new Error(`Key material must be 32 bytes, got ${keyMaterial.length}`);
    }
    if (salt.length !== 32) {
        throw new Error(`Salt must be 32 bytes, got ${salt.length}`);
    }
    const info = new TextEncoder().encode(HKDF_INFO);
    return hkdf(sha256, keyMaterial, salt, info, 32);
}
//# sourceMappingURL=kdf.js.map