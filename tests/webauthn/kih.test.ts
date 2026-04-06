import { describe, it, expect } from 'vitest'
import { generateUserId, extractKey } from '../../src/webauthn/kih.js'
import { MODE_BYTE, USER_ID_SIZE, KEY_SIZE } from '../../src/types.js'
import { randomBytes } from '@noble/hashes/utils.js'

describe('user ID helpers', () => {
  describe('generateUserId', () => {
    it('produces a 33-byte buffer with 0x03 prefix', () => {
      const userId = generateUserId()
      expect(userId.length).toBe(USER_ID_SIZE)
      expect(userId[0]).toBe(MODE_BYTE)
    })

    it('generates different keys each time', () => {
      const a = generateUserId()
      const b = generateUserId()
      expect(a.slice(1)).not.toEqual(b.slice(1))
    })
  })

  describe('extractKey', () => {
    it('extracts the 32-byte key from a userHandle', () => {
      const userId = generateUserId()
      const key = extractKey(userId)
      expect(key.length).toBe(KEY_SIZE)
      expect(key).toEqual(userId.slice(1))
    })

    it('throws for wrong-size handle', () => {
      expect(() => extractKey(randomBytes(32))).toThrow('userHandle is 32 bytes')
    })

    it('throws for wrong prefix byte', () => {
      const handle = new Uint8Array(33)
      handle[0] = 0x01
      expect(() => extractKey(handle)).toThrow('Unrecognized userHandle format')
    })

    it('returns an independent copy (not a view)', () => {
      const userId = generateUserId()
      const key = extractKey(userId)
      key[0] = 0xff
      expect(userId[1]).not.toBe(0xff)
    })
  })
})
