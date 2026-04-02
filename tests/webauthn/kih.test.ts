import { describe, it, expect } from 'vitest'
import { generateKihUserId, detectMode, extractKihKey } from '../../src/webauthn/kih.js'
import { KIH_MODE_BYTE, KIH_USER_ID_SIZE, KIH_KEY_SIZE } from '../../src/types.js'
import { randomBytes } from '@noble/hashes/utils.js'

describe('KiH user ID helpers', () => {
  describe('generateKihUserId', () => {
    it('produces a 33-byte buffer with 0x03 prefix', () => {
      const userId = generateKihUserId()
      expect(userId.length).toBe(KIH_USER_ID_SIZE)
      expect(userId[0]).toBe(KIH_MODE_BYTE)
    })

    it('generates different keys each time', () => {
      const a = generateKihUserId()
      const b = generateKihUserId()
      expect(a.slice(1)).not.toEqual(b.slice(1))
    })
  })

  describe('detectMode', () => {
    it('returns "kih" for 33-byte handle with 0x03 prefix', () => {
      const handle = generateKihUserId()
      expect(detectMode(handle)).toBe('kih')
    })

    it('returns "prf" for 32-byte handle', () => {
      const handle = randomBytes(32)
      expect(detectMode(handle)).toBe('prf')
    })

    it('throws for unexpected length', () => {
      expect(() => detectMode(randomBytes(16))).toThrow('userHandle is 16 bytes')
    })

    it('throws for 33 bytes without 0x03 prefix', () => {
      const handle = new Uint8Array(33)
      handle[0] = 0x01
      expect(() => detectMode(handle)).toThrow('Unrecognized userHandle format')
    })
  })

  describe('extractKihKey', () => {
    it('extracts the 32-byte key from a KiH userHandle', () => {
      const userId = generateKihUserId()
      const key = extractKihKey(userId)
      expect(key.length).toBe(KIH_KEY_SIZE)
      expect(key).toEqual(userId.slice(1))
    })

    it('throws for non-KiH handle', () => {
      expect(() => extractKihKey(randomBytes(32))).toThrow('KiH userHandle is 32 bytes')
    })

    it('returns an independent copy (not a view)', () => {
      const userId = generateKihUserId()
      const key = extractKihKey(userId)
      key[0] = 0xff
      expect(userId[1]).not.toBe(0xff)
    })
  })
})
