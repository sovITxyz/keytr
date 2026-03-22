import { describe, it, expect } from 'vitest'
import { deriveKey } from '../../src/crypto/kdf.js'

describe('deriveKey', () => {
  it('produces 32-byte output from valid inputs', () => {
    const prfOutput = new Uint8Array(32).fill(0xab)
    const salt = new Uint8Array(32).fill(0xcd)
    const key = deriveKey(prfOutput, salt)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  })

  it('produces deterministic output for same inputs', () => {
    const prfOutput = new Uint8Array(32).fill(0x42)
    const salt = new Uint8Array(32).fill(0x13)
    const key1 = deriveKey(prfOutput, salt)
    const key2 = deriveKey(prfOutput, salt)
    expect(key1).toEqual(key2)
  })

  it('produces different output for different salts', () => {
    const prfOutput = new Uint8Array(32).fill(0x42)
    const salt1 = new Uint8Array(32).fill(0x01)
    const salt2 = new Uint8Array(32).fill(0x02)
    const key1 = deriveKey(prfOutput, salt1)
    const key2 = deriveKey(prfOutput, salt2)
    expect(key1).not.toEqual(key2)
  })

  it('produces different output for different PRF outputs', () => {
    const prf1 = new Uint8Array(32).fill(0x01)
    const prf2 = new Uint8Array(32).fill(0x02)
    const salt = new Uint8Array(32).fill(0xaa)
    expect(deriveKey(prf1, salt)).not.toEqual(deriveKey(prf2, salt))
  })

  it('rejects wrong PRF output length', () => {
    expect(() => deriveKey(new Uint8Array(16), new Uint8Array(32))).toThrow('PRF output must be 32 bytes')
  })

  it('rejects wrong salt length', () => {
    expect(() => deriveKey(new Uint8Array(32), new Uint8Array(16))).toThrow('Salt must be 32 bytes')
  })
})
