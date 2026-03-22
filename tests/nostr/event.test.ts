import { describe, it, expect } from 'vitest'
import { buildNostkeyEvent, parseNostkeyEvent } from '../../src/nostr/event.js'
import { NOSTKEY_EVENT_KIND, type NostkeyCredential } from '../../src/types.js'
import { base64url } from '@scure/base'

describe('nostr event', () => {
  const credentialId = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd])
  const credential: NostkeyCredential = {
    credentialId,
    credentialIdBase64url: base64url.encode(credentialId),
    rpId: 'nostkey.org',
    transports: ['internal', 'hybrid'] as AuthenticatorTransport[],
    prfSupported: true,
  }

  it('builds a valid event template', () => {
    const event = buildNostkeyEvent({
      credential,
      encryptedBlob: 'dGVzdA==',
      clientName: 'test-client',
    })

    expect(event.kind).toBe(NOSTKEY_EVENT_KIND)
    expect(event.content).toBe('dGVzdA==')
    expect(event.tags.find(t => t[0] === 'd')?.[1]).toBe(credential.credentialIdBase64url)
    expect(event.tags.find(t => t[0] === 'rp')?.[1]).toBe('nostkey.org')
    expect(event.tags.find(t => t[0] === 'algo')?.[1]).toBe('aes-256-gcm')
    expect(event.tags.find(t => t[0] === 'kdf')?.[1]).toBe('hkdf-sha256')
    expect(event.tags.find(t => t[0] === 'v')?.[1]).toBe('1')
    expect(event.tags.find(t => t[0] === 'client')?.[1]).toBe('test-client')
    expect(event.tags.find(t => t[0] === 'transports')).toEqual(['transports', 'internal', 'hybrid'])
  })

  it('round-trips through build and parse', () => {
    const event = buildNostkeyEvent({ credential, encryptedBlob: 'dGVzdA==' })
    const parsed = parseNostkeyEvent(event)

    expect(parsed.credentialIdBase64url).toBe(credential.credentialIdBase64url)
    expect(parsed.credentialId).toEqual(credentialId)
    expect(parsed.rpId).toBe('nostkey.org')
    expect(parsed.encryptedBlob).toBe('dGVzdA==')
    expect(parsed.version).toBe(1)
    expect(parsed.algorithm).toBe('aes-256-gcm')
    expect(parsed.kdf).toBe('hkdf-sha256')
    expect(parsed.transports).toEqual(['internal', 'hybrid'])
  })

  it('rejects wrong event kind', () => {
    expect(() => parseNostkeyEvent({
      kind: 1,
      content: '',
      tags: [],
    })).toThrow('Expected kind 30079')
  })

  it('rejects missing d tag', () => {
    expect(() => parseNostkeyEvent({
      kind: NOSTKEY_EVENT_KIND,
      content: '',
      tags: [['rp', 'nostkey.org']],
    })).toThrow('Missing "d" tag')
  })

  it('rejects missing rp tag', () => {
    expect(() => parseNostkeyEvent({
      kind: NOSTKEY_EVENT_KIND,
      content: '',
      tags: [['d', credential.credentialIdBase64url]],
    })).toThrow('Missing "rp" tag')
  })
})
