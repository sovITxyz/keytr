import { gcm } from '@noble/ciphers/aes.js'
import { base64 } from '@scure/base'
import type { DecryptOptions } from '../types.js'
import { DecryptionError } from '../errors.js'
import { deriveKey } from './kdf.js'
import { deserializeBlob } from './blob.js'
import { buildAad } from './encrypt.js'
import { safeZero } from './builtins.js'

/**
 * Decrypt a base64-encoded encrypted nsec blob using the passkey's embedded key.
 *
 * @returns 32-byte raw nsec private key
 */
export function decryptNsec(options: DecryptOptions): Uint8Array {
  const { encryptedBlob, keyMaterial, credentialId } = options

  let blobBytes: Uint8Array
  try {
    blobBytes = base64.decode(encryptedBlob)
  } catch {
    throw new DecryptionError('Invalid base64 in encrypted blob')
  }

  const blob = deserializeBlob(blobBytes)
  const key = deriveKey(keyMaterial, blob.hkdfSalt)
  const aad = buildAad(credentialId, options.version)

  try {
    const cipher = gcm(key, blob.iv, aad)
    const nsecBytes = cipher.decrypt(blob.ciphertext)

    if (nsecBytes.length !== 32) {
      throw new DecryptionError(`Decrypted key is ${nsecBytes.length} bytes, expected 32`)
    }

    return nsecBytes
  } catch (err) {
    if (err instanceof DecryptionError) throw err
    throw new DecryptionError('Decryption failed - wrong passkey or corrupted data')
  } finally {
    safeZero(key)
  }
}
