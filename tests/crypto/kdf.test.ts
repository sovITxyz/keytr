import { describe, it, expect } from 'vitest'
import { deriveKey } from '../../src/crypto/kdf.js'

describe('deriveKey', () => {
  it('produces 32-byte output from valid inputs', () => {
    const keyMaterial = new Uint8Array(32).fill(0xab)
    const salt = new Uint8Array(32).fill(0xcd)
    const key = deriveKey(keyMaterial, salt)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  })

  it('produces deterministic output for same inputs', () => {
    const keyMaterial = new Uint8Array(32).fill(0x42)
    const salt = new Uint8Array(32).fill(0x13)
    const key1 = deriveKey(keyMaterial, salt)
    const key2 = deriveKey(keyMaterial, salt)
    expect(key1).toEqual(key2)
  })

  it('produces different output for different salts', () => {
    const keyMaterial = new Uint8Array(32).fill(0x42)
    const salt1 = new Uint8Array(32).fill(0x01)
    const salt2 = new Uint8Array(32).fill(0x02)
    const key1 = deriveKey(keyMaterial, salt1)
    const key2 = deriveKey(keyMaterial, salt2)
    expect(key1).not.toEqual(key2)
  })

  it('produces different output for different key material', () => {
    const km1 = new Uint8Array(32).fill(0x01)
    const km2 = new Uint8Array(32).fill(0x02)
    const salt = new Uint8Array(32).fill(0xaa)
    expect(deriveKey(km1, salt)).not.toEqual(deriveKey(km2, salt))
  })

  it('rejects wrong key material length', () => {
    expect(() => deriveKey(new Uint8Array(16), new Uint8Array(32))).toThrow('Key material must be 32 bytes')
  })

  it('rejects wrong salt length', () => {
    expect(() => deriveKey(new Uint8Array(32), new Uint8Array(16))).toThrow('Salt must be 32 bytes')
  })
})
