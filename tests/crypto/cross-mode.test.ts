import { describe, it, expect } from 'vitest'
import { encryptNsec, buildAad } from '../../src/crypto/encrypt.js'
import { decryptNsec } from '../../src/crypto/decrypt.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { KEYTR_VERSION, KEYTR_KIH_VERSION } from '../../src/types.js'

describe('buildAad', () => {
  it('defaults to PRF version byte', () => {
    const credId = new Uint8Array([0xaa, 0xbb])
    const aad = buildAad(credId)
    // 'keytr' (5) + version (1) + credId (2) = 8 bytes
    expect(aad.length).toBe(8)
    expect(aad[5]).toBe(KEYTR_VERSION) // version byte
  })

  it('accepts explicit version byte', () => {
    const credId = new Uint8Array([0xaa])
    const aad = buildAad(credId, KEYTR_KIH_VERSION)
    expect(aad[5]).toBe(KEYTR_KIH_VERSION)
  })

  it('PRF and KiH AADs differ for same credentialId', () => {
    const credId = randomBytes(16)
    const prfAad = buildAad(credId, KEYTR_VERSION)
    const kihAad = buildAad(credId, KEYTR_KIH_VERSION)
    expect(prfAad).not.toEqual(kihAad)
  })
})

describe('cross-mode encryption isolation', () => {
  it('KiH-encrypted blob decrypts with KiH AAD version', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({
      nsecBytes,
      prfOutput: keyMaterial,
      credentialId,
      aadVersion: KEYTR_KIH_VERSION,
    })

    const decrypted = decryptNsec({
      encryptedBlob: blob,
      prfOutput: keyMaterial,
      credentialId,
      aadVersion: KEYTR_KIH_VERSION,
    })

    expect(decrypted).toEqual(nsecBytes)
  })

  it('PRF blob cannot be decrypted with KiH AAD version', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({
      nsecBytes,
      prfOutput: keyMaterial,
      credentialId,
      aadVersion: KEYTR_VERSION,
    })

    expect(() => decryptNsec({
      encryptedBlob: blob,
      prfOutput: keyMaterial,
      credentialId,
      aadVersion: KEYTR_KIH_VERSION,
    })).toThrow()
  })

  it('KiH blob cannot be decrypted with PRF AAD version', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({
      nsecBytes,
      prfOutput: keyMaterial,
      credentialId,
      aadVersion: KEYTR_KIH_VERSION,
    })

    expect(() => decryptNsec({
      encryptedBlob: blob,
      prfOutput: keyMaterial,
      credentialId,
    })).toThrow()
  })

  it('existing PRF roundtrip still works (no aadVersion = default v1)', () => {
    const nsecBytes = randomBytes(32)
    const prfOutput = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, prfOutput, credentialId })
    const decrypted = decryptNsec({ encryptedBlob: blob, prfOutput, credentialId })

    expect(decrypted).toEqual(nsecBytes)
  })
})
