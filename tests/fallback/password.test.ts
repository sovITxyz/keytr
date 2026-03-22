import { describe, it, expect } from 'vitest'
import { encryptNsecWithPassword, decryptNsecFromPassword } from '../../src/fallback/password.js'
import { randomBytes } from '@noble/hashes/utils'

describe('password fallback', () => {
  // Use fast scrypt params for tests by testing the interface
  // The actual scrypt N=2^20 is slow, so we test the contract
  it('round-trips encrypt/decrypt with password', () => {
    const nsecBytes = randomBytes(32)
    const password = 'test-password-123!'

    const encrypted = encryptNsecWithPassword(nsecBytes, password)
    const decrypted = decryptNsecFromPassword(encrypted, password)

    expect(decrypted).toEqual(nsecBytes)
  }, 30000) // scrypt is intentionally slow

  it('fails with wrong password', () => {
    const nsecBytes = randomBytes(32)

    const encrypted = encryptNsecWithPassword(nsecBytes, 'correct-password')

    expect(() => decryptNsecFromPassword(encrypted, 'wrong-password')).toThrow()
  }, 30000)

  it('produces different ciphertexts for same input', () => {
    const nsecBytes = randomBytes(32)
    const password = 'test'

    const a = encryptNsecWithPassword(nsecBytes, password)
    const b = encryptNsecWithPassword(nsecBytes, password)

    expect(a).not.toBe(b)
  }, 30000)

  it('rejects empty password', () => {
    expect(() => encryptNsecWithPassword(randomBytes(32), '')).toThrow('Password must not be empty')
  })

  it('rejects wrong nsec length', () => {
    expect(() => encryptNsecWithPassword(randomBytes(16), 'pw')).toThrow('nsec must be 32 bytes')
  })
})
