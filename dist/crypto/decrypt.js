import { gcm } from '@noble/ciphers/aes.js';
import { base64 } from '@scure/base';
import { KEYTR_VERSION } from '../types.js';
import { DecryptionError } from '../errors.js';
import { deriveKey } from './kdf.js';
import { deserializeBlob } from './blob.js';
import { buildAad } from './encrypt.js';
/**
 * Decrypt a base64-encoded encrypted nsec blob using a PRF-derived key.
 *
 * @returns 32-byte raw nsec private key
 */
export function decryptNsec(options) {
    const { encryptedBlob, prfOutput, credentialId } = options;
    let blobBytes;
    try {
        blobBytes = base64.decode(encryptedBlob);
    }
    catch {
        throw new DecryptionError('Invalid base64 in encrypted blob');
    }
    const blob = deserializeBlob(blobBytes);
    const key = deriveKey(prfOutput, blob.hkdfSalt);
    const aad = buildAad(credentialId, options.aadVersion ?? KEYTR_VERSION);
    try {
        const cipher = gcm(key, blob.iv, aad);
        const nsecBytes = cipher.decrypt(blob.ciphertext);
        if (nsecBytes.length !== 32) {
            throw new DecryptionError(`Decrypted key is ${nsecBytes.length} bytes, expected 32`);
        }
        return nsecBytes;
    }
    catch (err) {
        if (err instanceof DecryptionError)
            throw err;
        throw new DecryptionError('Decryption failed - wrong passkey or corrupted data');
    }
    finally {
        key.fill(0);
    }
}
//# sourceMappingURL=decrypt.js.map