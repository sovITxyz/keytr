import { randomBytes } from '@noble/hashes/utils.js'
import { MODE_BYTE, KEY_SIZE, USER_ID_SIZE } from '../types.js'
import { KeytrError } from '../errors.js'
import { safeSlice, safeSet } from '../crypto/builtins.js'

/**
 * Generate a 33-byte user.id: [0x03 || random_key(32)].
 * The mode byte allows future format detection if needed.
 */
export function generateUserId(): Uint8Array {
  const userId = new Uint8Array(USER_ID_SIZE)
  userId[0] = MODE_BYTE
  safeSet(userId, randomBytes(KEY_SIZE), 1)
  return userId
}

/**
 * Extract the 32-byte encryption key from a userHandle.
 * Validates the expected format: 33 bytes with 0x03 prefix.
 */
export function extractKey(userHandle: Uint8Array): Uint8Array {
  if (userHandle.length < USER_ID_SIZE) {
    throw new KeytrError(
      `userHandle is ${userHandle.length} bytes, expected ${USER_ID_SIZE}. ` +
      `The authenticator may have truncated user.id — the encryption key is incomplete.`
    )
  }
  if (userHandle.length !== USER_ID_SIZE || userHandle[0] !== MODE_BYTE) {
    throw new KeytrError(
      `Unrecognized userHandle format: ${userHandle.length} bytes, ` +
      `byte[0]=0x${userHandle[0].toString(16).padStart(2, '0')} (expected 0x${MODE_BYTE.toString(16).padStart(2, '0')})`
    )
  }
  return safeSlice(userHandle, 1, 1 + KEY_SIZE)
}
