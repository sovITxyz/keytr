import { describe, it, expect } from 'vitest'
import { encryptNsec, buildAad } from '../../src/crypto/encrypt.js'
import { decryptNsec } from '../../src/crypto/decrypt.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { KEYTR_VERSION } from '../../src/types.js'

describe('buildAad', () => {
  it('uses version 3 by default', () => {
    const credId = new Uint8Array([0xaa, 0xbb])
    const aad = buildAad(credId)
    // 'keytr' (5) + version (1) + credId (2) = 8 bytes
    expect(aad.length).toBe(8)
    expect(aad[5]).toBe(KEYTR_VERSION) // version byte = 3
  })

  it('accepts custom version', () => {
    const credId = new Uint8Array([0xaa, 0xbb])
    const aad = buildAad(credId, 1)
    expect(aad.length).toBe(8)
    expect(aad[5]).toBe(1)
  })
})

describe('encryption roundtrip', () => {
  it('encrypts and decrypts correctly', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, keyMaterial, credentialId })

    const decrypted = decryptNsec({
      encryptedBlob: blob,
      keyMaterial,
      credentialId,
    })

    expect(decrypted).toEqual(nsecBytes)
  })

  it('fails with wrong key material', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, keyMaterial, credentialId })

    const wrongKey = randomBytes(32)
    expect(() => decryptNsec({
      encryptedBlob: blob,
      keyMaterial: wrongKey,
      credentialId,
    })).toThrow()
  })

  it('fails with wrong credential ID (AAD mismatch)', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, keyMaterial, credentialId })

    const wrongCred = randomBytes(16)
    expect(() => decryptNsec({
      encryptedBlob: blob,
      keyMaterial,
      credentialId: wrongCred,
    })).toThrow()
  })
})
