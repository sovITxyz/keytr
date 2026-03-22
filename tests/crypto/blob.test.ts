import { describe, it, expect } from 'vitest'
import { serializeBlob, deserializeBlob } from '../../src/crypto/blob.js'
import { KEYTR_VERSION, type EncryptedNsecBlob } from '../../src/types.js'

describe('blob serialization', () => {
  const validBlob: EncryptedNsecBlob = {
    version: KEYTR_VERSION,
    iv: new Uint8Array(12).fill(0x11),
    hkdfSalt: new Uint8Array(32).fill(0x22),
    ciphertext: new Uint8Array(48).fill(0x33),
  }

  it('serializes to 93 bytes', () => {
    const data = serializeBlob(validBlob)
    expect(data.length).toBe(93)
  })

  it('round-trips correctly', () => {
    const data = serializeBlob(validBlob)
    const parsed = deserializeBlob(data)
    expect(parsed.version).toBe(KEYTR_VERSION)
    expect(parsed.iv).toEqual(validBlob.iv)
    expect(parsed.hkdfSalt).toEqual(validBlob.hkdfSalt)
    expect(parsed.ciphertext).toEqual(validBlob.ciphertext)
  })

  it('stores version as first byte', () => {
    const data = serializeBlob(validBlob)
    expect(data[0]).toBe(KEYTR_VERSION)
  })

  it('rejects wrong IV length', () => {
    expect(() => serializeBlob({ ...validBlob, iv: new Uint8Array(8) })).toThrow()
  })

  it('rejects wrong salt length', () => {
    expect(() => serializeBlob({ ...validBlob, hkdfSalt: new Uint8Array(16) })).toThrow()
  })

  it('rejects wrong ciphertext length', () => {
    expect(() => serializeBlob({ ...validBlob, ciphertext: new Uint8Array(32) })).toThrow()
  })

  it('rejects wrong blob size on deserialize', () => {
    expect(() => deserializeBlob(new Uint8Array(50))).toThrow('Expected 93 bytes')
  })

  it('rejects unsupported version on deserialize', () => {
    const data = serializeBlob(validBlob)
    data[0] = 99
    expect(() => deserializeBlob(data)).toThrow('Unsupported blob version')
  })
})
