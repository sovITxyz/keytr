import { randomBytes } from '@noble/hashes/utils.js'
import {
  KIH_MODE_BYTE,
  KIH_KEY_SIZE,
  KIH_USER_ID_SIZE,
  PRF_USER_ID_SIZE,
  type KeytrMode,
} from '../types.js'
import { KeytrError } from '../errors.js'

/**
 * Generate a 33-byte KiH user.id: [0x03 || random_key(32)].
 * The mode byte allows discoverable login to distinguish KiH from PRF credentials.
 */
export function generateKihUserId(): Uint8Array {
  const userId = new Uint8Array(KIH_USER_ID_SIZE)
  userId[0] = KIH_MODE_BYTE
  userId.set(randomBytes(KIH_KEY_SIZE), 1)
  return userId
}

/**
 * Detect whether a userHandle represents a PRF or KiH credential.
 * - 32 bytes → PRF (userHandle is the hex-encoded pubkey)
 * - 33 bytes with byte[0] === 0x03 → KiH
 */
export function detectMode(userHandle: Uint8Array): KeytrMode {
  if (userHandle.length === KIH_USER_ID_SIZE && userHandle[0] === KIH_MODE_BYTE) {
    return 'kih'
  }
  if (userHandle.length === PRF_USER_ID_SIZE) {
    return 'prf'
  }

  // Truncation detection: if shorter than expected, the authenticator likely truncated user.id
  if (userHandle.length < PRF_USER_ID_SIZE) {
    throw new KeytrError(
      `userHandle is ${userHandle.length} bytes, expected ${PRF_USER_ID_SIZE} (PRF) or ${KIH_USER_ID_SIZE} (KiH). ` +
      `The authenticator may have truncated user.id — this passkey cannot be used for decryption.`
    )
  }

  throw new KeytrError(
    `Unrecognized userHandle format: ${userHandle.length} bytes` +
    (userHandle.length === KIH_USER_ID_SIZE
      ? `, byte[0]=0x${userHandle[0].toString(16).padStart(2, '0')} (expected 0x${KIH_MODE_BYTE.toString(16).padStart(2, '0')})`
      : `. Expected ${PRF_USER_ID_SIZE} (PRF) or ${KIH_USER_ID_SIZE} (KiH).`)
  )
}

/**
 * Extract the 32-byte encryption key from a KiH userHandle.
 * Caller must verify detectMode() === 'kih' first.
 */
export function extractKihKey(userHandle: Uint8Array): Uint8Array {
  if (userHandle.length < KIH_USER_ID_SIZE) {
    throw new KeytrError(
      `KiH userHandle is ${userHandle.length} bytes, expected ${KIH_USER_ID_SIZE}. ` +
      `The authenticator may have truncated user.id — the encryption key is incomplete.`
    )
  }
  if (userHandle.length !== KIH_USER_ID_SIZE || userHandle[0] !== KIH_MODE_BYTE) {
    throw new KeytrError(
      `Not a valid KiH userHandle: ${userHandle.length} bytes, ` +
      `byte[0]=0x${userHandle[0].toString(16).padStart(2, '0')}`
    )
  }
  return userHandle.slice(1, 1 + KIH_KEY_SIZE)
}
