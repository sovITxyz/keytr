import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/hashes/utils'
import { base64 } from '@scure/base'
import { KEYTR_VERSION, type EncryptOptions } from '../types.js'
import { EncryptionError } from '../errors.js'
import { deriveKey } from './kdf.js'
import { serializeBlob } from './blob.js'

/**
 * Build the Additional Authenticated Data (AAD) for AES-GCM.
 * AAD binds ciphertext to the credential ID and version,
 * preventing substitution attacks.
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
 * Encrypt a 32-byte nsec using a PRF-derived key.
 *
 * @returns Base64-encoded encrypted blob (93 bytes binary -> ~124 chars)
 */
export function encryptNsec(options: EncryptOptions): string {
  const { nsecBytes, prfOutput, credentialId } = options

  if (nsecBytes.length !== 32) {
    throw new EncryptionError(`nsec must be 32 bytes, got ${nsecBytes.length}`)
  }

  const iv = randomBytes(12)
  const hkdfSalt = randomBytes(32)
  const key = deriveKey(prfOutput, hkdfSalt)
  const aad = buildAad(credentialId)

  try {
    const cipher = gcm(key, iv, aad)
    const ciphertext = cipher.encrypt(nsecBytes)

    const blob = serializeBlob({
      version: KEYTR_VERSION,
      iv,
      hkdfSalt,
      ciphertext,
    })

    return base64.encode(blob)
  } finally {
    // Best-effort memory cleanup
    key.fill(0)
  }
}
