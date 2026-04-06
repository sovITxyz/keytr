import { gcm } from '@noble/ciphers/aes.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import { BLOB_VERSION, KEYTR_VERSION, type EncryptOptions } from '../types.js'
import { EncryptionError } from '../errors.js'
import { deriveKey } from './kdf.js'
import { serializeBlob } from './blob.js'

/**
 * Build the Additional Authenticated Data (AAD) for AES-GCM.
 * AAD = "keytr" || version_byte || credentialId
 */
export function buildAad(credentialId: Uint8Array, version?: number): Uint8Array {
  const prefix = new TextEncoder().encode('keytr')
  const aad = new Uint8Array(prefix.length + 1 + credentialId.length)
  aad.set(prefix, 0)
  aad[prefix.length] = version ?? KEYTR_VERSION
  aad.set(credentialId, prefix.length + 1)
  return aad
}

/**
 * Encrypt a 32-byte nsec using a key derived from the passkey's embedded key.
 *
 * @returns Base64-encoded encrypted blob (93 bytes binary -> ~124 chars)
 */
export function encryptNsec(options: EncryptOptions): string {
  const { nsecBytes, keyMaterial, credentialId } = options

  if (nsecBytes.length !== 32) {
    throw new EncryptionError(`nsec must be 32 bytes, got ${nsecBytes.length}`)
  }

  const iv = randomBytes(12)
  const hkdfSalt = randomBytes(32)
  const key = deriveKey(keyMaterial, hkdfSalt)
  const aad = buildAad(credentialId, options.version)

  try {
    const cipher = gcm(key, iv, aad)
    const ciphertext = cipher.encrypt(nsecBytes)

    const blob = serializeBlob({
      version: BLOB_VERSION,
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
