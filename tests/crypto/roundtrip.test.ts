import { describe, it, expect } from 'vitest'
import { encryptNsec } from '../../src/crypto/encrypt.js'
import { decryptNsec } from '../../src/crypto/decrypt.js'
import { randomBytes } from '@noble/hashes/utils'

describe('encrypt/decrypt roundtrip', () => {
  it('encrypts and decrypts correctly', () => {
    const nsecBytes = randomBytes(32)
    const prfOutput = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, prfOutput, credentialId })

    const decrypted = decryptNsec({
      encryptedBlob: blob,
      prfOutput,
      credentialId,
    })

    expect(decrypted).toEqual(nsecBytes)
  })

  it('fails with wrong PRF output', () => {
    const nsecBytes = randomBytes(32)
    const prfOutput = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, prfOutput, credentialId })

    const wrongPrf = randomBytes(32)
    expect(() => decryptNsec({
      encryptedBlob: blob,
      prfOutput: wrongPrf,
      credentialId,
    })).toThrow()
  })

  it('fails with wrong credential ID (AAD mismatch)', () => {
    const nsecBytes = randomBytes(32)
    const prfOutput = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, prfOutput, credentialId })

    const wrongCred = randomBytes(16)
    expect(() => decryptNsec({
      encryptedBlob: blob,
      prfOutput,
      credentialId: wrongCred,
    })).toThrow()
  })

  it('produces different ciphertexts for same input (random IV/salt)', () => {
    const nsecBytes = randomBytes(32)
    const prfOutput = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob1 = encryptNsec({ nsecBytes, prfOutput, credentialId })
    const blob2 = encryptNsec({ nsecBytes, prfOutput, credentialId })

    expect(blob1).not.toBe(blob2)
  })

  it('rejects invalid base64 blob', () => {
    expect(() => decryptNsec({
      encryptedBlob: 'not-valid-base64!!!',
      prfOutput: randomBytes(32),
      credentialId: randomBytes(16),
    })).toThrow()
  })

  it('rejects wrong nsec length', () => {
    expect(() => encryptNsec({
      nsecBytes: randomBytes(16),
      prfOutput: randomBytes(32),
      credentialId: randomBytes(16),
    })).toThrow('nsec must be 32 bytes')
  })
})
