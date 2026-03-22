import { describe, it, expect } from 'vitest'
import { encryptNsecWithPassword, decryptNsecFromPassword } from '../../src/fallback/password.js'
import { randomBytes } from '@noble/hashes/utils'

const FAST_SCRYPT = { N: 1024, r: 8, p: 1 }

describe('password fallback', () => {
  it('round-trips encrypt/decrypt with password', () => {
    const nsecBytes = randomBytes(32)
    const password = 'test-password-123!'

    const encrypted = encryptNsecWithPassword(nsecBytes, password, FAST_SCRYPT)
    const decrypted = decryptNsecFromPassword(encrypted, password, FAST_SCRYPT)

    expect(decrypted).toEqual(nsecBytes)
  })

  it('fails with wrong password', () => {
    const nsecBytes = randomBytes(32)

    const encrypted = encryptNsecWithPassword(nsecBytes, 'correct-password', FAST_SCRYPT)

    expect(() => decryptNsecFromPassword(encrypted, 'wrong-password', FAST_SCRYPT)).toThrow()
  })

  it('produces different ciphertexts for same input', () => {
    const nsecBytes = randomBytes(32)
    const password = 'test'

    const a = encryptNsecWithPassword(nsecBytes, password, FAST_SCRYPT)
    const b = encryptNsecWithPassword(nsecBytes, password, FAST_SCRYPT)

    expect(a).not.toBe(b)
  })

  it('rejects empty password', () => {
    expect(() => encryptNsecWithPassword(randomBytes(32), '')).toThrow('Password must not be empty')
  })

  it('rejects wrong nsec length', () => {
    expect(() => encryptNsecWithPassword(randomBytes(16), 'pw')).toThrow('nsec must be 32 bytes')
  })
})
