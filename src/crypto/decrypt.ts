import { gcm } from '@noble/ciphers/aes'
import { base64 } from '@scure/base'
import { KEYTR_VERSION, type DecryptOptions } from '../types.js'
import { DecryptionError } from '../errors.js'
import { deriveKey } from './kdf.js'
import { deserializeBlob } from './blob.js'

/**
 * Rebuild the AAD for verification (must match what was used during encryption).
 */
function buildAad(credentialId: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode('keytr')
  const aad = new Uint8Array(prefix.length + 1 + credentialId.length)
  aad.set(prefix, 0)
  aad[prefix.length] = KEYTR_VERSION
  aad.set(credentialId, prefix.length + 1)
  return aad
}

/**
 * Decrypt a base64-encoded encrypted nsec blob using a PRF-derived key.
 *
 * @returns 32-byte raw nsec private key
 */
export function decryptNsec(options: DecryptOptions): Uint8Array {
  const { encryptedBlob, prfOutput, credentialId } = options

  let blobBytes: Uint8Array
  try {
    blobBytes = base64.decode(encryptedBlob)
  } catch {
    throw new DecryptionError('Invalid base64 in encrypted blob')
  }

  const blob = deserializeBlob(blobBytes)
  const key = deriveKey(prfOutput, blob.hkdfSalt)
  const aad = buildAad(credentialId)

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
    key.fill(0)
  }
}
