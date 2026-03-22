import { describe, it, expect } from 'vitest'
import { buildKeytrEvent, parseKeytrEvent } from '../../src/nostr/event.js'
import { KEYTR_EVENT_KIND, type KeytrCredential } from '../../src/types.js'
import { base64url } from '@scure/base'

describe('nostr event', () => {
  const credentialId = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd])
  const credential: KeytrCredential = {
    credentialId,
    credentialIdBase64url: base64url.encode(credentialId),
    rpId: 'keytr.org',
    transports: ['internal', 'hybrid'] as AuthenticatorTransport[],
    prfSupported: true,
  }

  it('builds a valid event template', () => {
    const event = buildKeytrEvent({
      credential,
      encryptedBlob: 'dGVzdA==',
      clientName: 'test-client',
    })

    expect(event.kind).toBe(KEYTR_EVENT_KIND)
    expect(event.content).toBe('dGVzdA==')
    expect(event.tags.find(t => t[0] === 'd')?.[1]).toBe(credential.credentialIdBase64url)
    expect(event.tags.find(t => t[0] === 'rp')?.[1]).toBe('keytr.org')
    expect(event.tags.find(t => t[0] === 'algo')?.[1]).toBe('aes-256-gcm')
    expect(event.tags.find(t => t[0] === 'kdf')?.[1]).toBe('hkdf-sha256')
    expect(event.tags.find(t => t[0] === 'v')?.[1]).toBe('1')
    expect(event.tags.find(t => t[0] === 'client')?.[1]).toBe('test-client')
    expect(event.tags.find(t => t[0] === 'transports')).toEqual(['transports', 'internal', 'hybrid'])
  })

  it('round-trips through build and parse', () => {
    const event = buildKeytrEvent({ credential, encryptedBlob: 'dGVzdA==' })
    const parsed = parseKeytrEvent(event)

    expect(parsed.credentialIdBase64url).toBe(credential.credentialIdBase64url)
    expect(parsed.credentialId).toEqual(credentialId)
    expect(parsed.rpId).toBe('keytr.org')
    expect(parsed.encryptedBlob).toBe('dGVzdA==')
    expect(parsed.version).toBe(1)
    expect(parsed.algorithm).toBe('aes-256-gcm')
    expect(parsed.kdf).toBe('hkdf-sha256')
    expect(parsed.transports).toEqual(['internal', 'hybrid'])
  })

  it('rejects wrong event kind', () => {
    expect(() => parseKeytrEvent({
      kind: 1,
      content: '',
      tags: [],
    })).toThrow('Expected kind 30079')
  })

  it('rejects missing d tag', () => {
    expect(() => parseKeytrEvent({
      kind: KEYTR_EVENT_KIND,
      content: '',
      tags: [['rp', 'keytr.org']],
    })).toThrow('Missing "d" tag')
  })

  it('rejects missing rp tag', () => {
    expect(() => parseKeytrEvent({
      kind: KEYTR_EVENT_KIND,
      content: '',
      tags: [['d', credential.credentialIdBase64url]],
    })).toThrow('Missing "rp" tag')
  })
})
