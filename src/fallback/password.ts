import { scrypt } from '@noble/hashes/scrypt'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/hashes/utils'
import { base64 } from '@scure/base'
import { EncryptionError, DecryptionError } from '../errors.js'

/**
 * NIP-49 compatible password-based nsec encryption.
 *
 * Used as a fallback when PRF extension is not available.
 * Uses scrypt for key derivation + AES-256-GCM for encryption.
 *
 * Blob format:
 *   [0]      version (0x01)
 *   [1..16]  scrypt salt (16 bytes)
 *   [17..28] IV (12 bytes)
 *   [29..76] ciphertext (48 bytes: 32 nsec + 16 GCM tag)
 *   Total: 77 bytes
 */

const VERSION = 0x01
const SALT_LEN = 16
const IV_LEN = 12
const CT_LEN = 48
const BLOB_SIZE = 1 + SALT_LEN + IV_LEN + CT_LEN

// scrypt params: N=2^20, r=8, p=1 (strong, ~1s on modern hardware)
const SCRYPT_N = 1048576
const SCRYPT_R = 8
const SCRYPT_P = 1

/** Encrypt nsec with a password using scrypt + AES-256-GCM */
export function encryptNsecWithPassword(
  nsecBytes: Uint8Array,
  password: string
): string {
  if (nsecBytes.length !== 32) {
    throw new EncryptionError(`nsec must be 32 bytes, got ${nsecBytes.length}`)
  }
  if (!password || password.length === 0) {
    throw new EncryptionError('Password must not be empty')
  }

  const salt = randomBytes(SALT_LEN)
  const iv = randomBytes(IV_LEN)
  const passwordBytes = new TextEncoder().encode(password)

  const key = scrypt(passwordBytes, salt, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: 32 })

  try {
    const cipher = gcm(key, iv)
    const ciphertext = cipher.encrypt(nsecBytes)

    const blob = new Uint8Array(BLOB_SIZE)
    blob[0] = VERSION
    blob.set(salt, 1)
    blob.set(iv, 1 + SALT_LEN)
    blob.set(ciphertext, 1 + SALT_LEN + IV_LEN)

    return base64.encode(blob)
  } finally {
    key.fill(0)
  }
}

/** Decrypt nsec from a password-encrypted blob */
export function decryptNsecFromPassword(
  encryptedBlob: string,
  password: string
): Uint8Array {
  let data: Uint8Array
  try {
    data = base64.decode(encryptedBlob)
  } catch {
    throw new DecryptionError('Invalid base64 encoding')
  }

  if (data.length !== BLOB_SIZE) {
    throw new DecryptionError(`Expected ${BLOB_SIZE} bytes, got ${data.length}`)
  }

  const version = data[0]
  if (version !== VERSION) {
    throw new DecryptionError(`Unsupported version: ${version}`)
  }

  const salt = data.slice(1, 1 + SALT_LEN)
  const iv = data.slice(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN)
  const ciphertext = data.slice(1 + SALT_LEN + IV_LEN)

  const passwordBytes = new TextEncoder().encode(password)
  const key = scrypt(passwordBytes, salt, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: 32 })

  try {
    const cipher = gcm(key, iv)
    const nsecBytes = cipher.decrypt(ciphertext)

    if (nsecBytes.length !== 32) {
      throw new DecryptionError(`Decrypted key is ${nsecBytes.length} bytes, expected 32`)
    }

    return nsecBytes
  } catch (err) {
    if (err instanceof DecryptionError) throw err
    throw new DecryptionError('Decryption failed - wrong password or corrupted data')
  } finally {
    key.fill(0)
  }
}
