import { describe, it, expect } from 'vitest'
import {
  generateNsec,
  encodeNsec,
  decodeNsec,
  encodeNpub,
  decodeNpub,
  nsecToNpub,
  nsecToHexPubkey,
} from '../../src/nostr/keys.js'

describe('nostr keys', () => {
  it('generates 32-byte nsec', () => {
    const nsec = generateNsec()
    expect(nsec).toBeInstanceOf(Uint8Array)
    expect(nsec.length).toBe(32)
  })

  it('generates unique keys', () => {
    const a = generateNsec()
    const b = generateNsec()
    expect(a).not.toEqual(b)
  })

  it('round-trips nsec through bech32', () => {
    const nsecBytes = generateNsec()
    const encoded = encodeNsec(nsecBytes)
    expect(encoded).toMatch(/^nsec1/)
    const decoded = decodeNsec(encoded)
    expect(decoded).toEqual(nsecBytes)
  })

  it('derives npub from nsec', () => {
    const nsecBytes = generateNsec()
    const npub = nsecToNpub(nsecBytes)
    expect(npub).toMatch(/^npub1/)
  })

  it('derives consistent hex pubkey', () => {
    const nsecBytes = generateNsec()
    const hex = nsecToHexPubkey(nsecBytes)
    expect(hex).toMatch(/^[0-9a-f]{64}$/)
    // Same input = same output
    expect(nsecToHexPubkey(nsecBytes)).toBe(hex)
  })

  it('round-trips npub through bech32', () => {
    const nsecBytes = generateNsec()
    const npub = nsecToNpub(nsecBytes)
    const pubkeyBytes = decodeNpub(npub)
    const npub2 = encodeNpub(pubkeyBytes)
    expect(npub2).toBe(npub)
  })

  it('rejects wrong nsec prefix', () => {
    const nsecBytes = generateNsec()
    const npub = nsecToNpub(nsecBytes)
    expect(() => decodeNsec(npub)).toThrow('Expected nsec prefix')
  })

  it('rejects wrong npub prefix', () => {
    const nsecBytes = generateNsec()
    const nsec = encodeNsec(nsecBytes)
    expect(() => decodeNpub(nsec)).toThrow('Expected npub prefix')
  })
})
