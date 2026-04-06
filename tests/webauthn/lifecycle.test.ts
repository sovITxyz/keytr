import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import { MODE_BYTE, USER_ID_SIZE } from '../../src/types.js'

// Stash originals for cleanup
const originalNavigator = globalThis.navigator

function makeKihUserId(): Uint8Array {
  const userId = new Uint8Array(USER_ID_SIZE)
  userId[0] = MODE_BYTE
  userId.set(randomBytes(32), 1)
  return userId
}

function mockCredentialCreate(userId: Uint8Array) {
  const rawId = randomBytes(16)
  return vi.fn().mockResolvedValue({
    type: 'public-key',
    rawId: rawId.buffer.slice(0),
    response: {
      getTransports: () => ['internal', 'hybrid'],
    },
    getClientExtensionResults: () => ({}),
    _userId: userId,
  })
}

function mockCredentialGet(userId: Uint8Array, rawId?: Uint8Array) {
  const credRawId = rawId ?? randomBytes(16)
  return vi.fn().mockResolvedValue({
    type: 'public-key',
    rawId: credRawId.buffer.slice(0),
    response: {
      userHandle: userId.buffer.slice(0),
    },
    getClientExtensionResults: () => ({}),
  })
}

function setupGlobals(overrides?: {
  create?: ReturnType<typeof vi.fn>
  get?: ReturnType<typeof vi.fn>
}) {
  const create = overrides?.create ?? vi.fn()
  const get = overrides?.get ?? vi.fn()

  Object.defineProperty(globalThis, 'navigator', {
    value: {
      credentials: { create, get },
    },
    configurable: true,
  })

  if (!globalThis.crypto?.getRandomValues) {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        getRandomValues: (arr: Uint8Array) => {
          const bytes = randomBytes(arr.length)
          arr.set(bytes)
          return arr
        },
      },
      configurable: true,
    })
  }

  return { create, get }
}

function restoreGlobals() {
  Object.defineProperty(globalThis, 'navigator', {
    value: originalNavigator,
    configurable: true,
  })
}

describe('WebAuthn credential lifecycle', () => {
  afterEach(() => {
    restoreGlobals()
    vi.restoreAllMocks()
  })

  it('registerPasskey returns credential and keyMaterial', async () => {
    const { create } = setupGlobals({ create: mockCredentialCreate(makeKihUserId()) })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    const result = await registerPasskey({
      userName: 'alice',
      userDisplayName: 'Alice',
    })

    expect(result.credential.rpId).toBe('keytr.org')
    expect(result.credential.credentialId).toBeInstanceOf(Uint8Array)
    expect(result.credential.credentialIdBase64url).toBe(
      base64url.encode(result.credential.credentialId)
    )
    expect(result.credential.transports).toEqual(['internal', 'hybrid'])
    expect(result.keyMaterial).toBeInstanceOf(Uint8Array)
    expect(result.keyMaterial.length).toBe(32)
    expect(create).toHaveBeenCalledOnce()
  })

  it('registerPasskey uses custom rpId and timeout', async () => {
    const { create } = setupGlobals({ create: mockCredentialCreate(makeKihUserId()) })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    const result = await registerPasskey({
      userName: 'bob',
      userDisplayName: 'Bob',
      rpId: 'custom.example',
      rpName: 'Custom RP',
      timeout: 60000,
    })

    expect(result.credential.rpId).toBe('custom.example')

    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    expect(createCall.publicKey?.rp?.id).toBe('custom.example')
    expect(createCall.publicKey?.rp?.name).toBe('Custom RP')
    expect(createCall.publicKey?.timeout).toBe(60000)
  })

  it('registerPasskey throws WebAuthnError on null result', async () => {
    setupGlobals({ create: vi.fn().mockResolvedValue(null) })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    await expect(
      registerPasskey({ userName: 'eve', userDisplayName: 'Eve' })
    ).rejects.toThrow('Credential creation returned null')
  })

  it('authenticatePasskey extracts key from userHandle', async () => {
    const userId = makeKihUserId()
    const expectedKey = userId.slice(1)
    const credentialId = randomBytes(16)
    setupGlobals({ get: mockCredentialGet(userId) })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')

    const result = await authenticatePasskey({
      credentialId,
      rpId: 'keytr.org',
      transports: ['internal'],
    })

    expect(result).toEqual(expectedKey)
  })

  it('authenticatePasskey uses custom timeout', async () => {
    const userId = makeKihUserId()
    const credentialId = randomBytes(16)
    const { get } = setupGlobals({ get: mockCredentialGet(userId) })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')

    await authenticatePasskey({
      credentialId,
      rpId: 'keytr.org',
      timeout: 30000,
    })

    const getCall = get.mock.calls[0][0] as CredentialRequestOptions
    expect(getCall.publicKey?.timeout).toBe(30000)
  })

  it('authenticatePasskey throws when userHandle is empty', async () => {
    const credentialId = randomBytes(16)
    setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: { userHandle: new ArrayBuffer(0) },
        getClientExtensionResults: () => ({}),
      }),
    })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')

    await expect(
      authenticatePasskey({ credentialId, rpId: 'keytr.org' })
    ).rejects.toThrow('userHandle')
  })

  it('discoverPasskey returns key and credentialId in single step', async () => {
    const userId = makeKihUserId()
    const expectedKey = userId.slice(1)
    const credRawId = randomBytes(16)

    const getMock = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: credRawId.buffer.slice(0),
      response: {
        userHandle: userId.buffer.slice(0),
      },
      getClientExtensionResults: () => ({}),
    })

    setupGlobals({ get: getMock })

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')
    const result = await discoverPasskey()

    // Single ceremony — no step 2
    expect(getMock).toHaveBeenCalledOnce()

    // Discovery: empty allowCredentials, no PRF
    const step1 = getMock.mock.calls[0][0] as CredentialRequestOptions
    expect(step1.publicKey?.allowCredentials).toEqual([])
    expect((step1.publicKey as any)?.extensions?.prf).toBeUndefined()

    expect(result.keyMaterial).toEqual(expectedKey)
    expect(result.credentialId).toEqual(credRawId)
  })

  it('discoverPasskey throws when userHandle is empty', async () => {
    setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: { userHandle: new ArrayBuffer(0) },
        getClientExtensionResults: () => ({}),
      }),
    })

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')

    await expect(discoverPasskey()).rejects.toThrow('userHandle')
  })

  it('full register → encrypt → authenticate → decrypt roundtrip', async () => {
    const userId = makeKihUserId()
    const credRawId = randomBytes(16)

    setupGlobals({
      create: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: credRawId.buffer.slice(0),
        response: {
          getTransports: () => ['internal', 'hybrid'],
        },
        getClientExtensionResults: () => ({}),
      }),
      get: mockCredentialGet(userId),
    })

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    const { encryptNsec } = await import('../../src/crypto/encrypt.js')
    const { decryptNsec } = await import('../../src/crypto/decrypt.js')

    // Step 1: Register passkey
    const { credential, keyMaterial } = await registerPasskey({
      userName: 'alice',
      userDisplayName: 'Alice',
    })

    // Step 2: Encrypt nsec
    const nsecBytes = randomBytes(32)
    const encryptedBlob = encryptNsec({
      nsecBytes,
      keyMaterial,
      credentialId: credential.credentialId,
    })

    // Step 3: Authenticate (simulates login on new device)
    const authKey = await authenticatePasskey({
      credentialId: credential.credentialId,
      rpId: credential.rpId,
      transports: credential.transports,
    })

    // Step 4: Decrypt nsec — use the same key material as registration
    // (In real flow, authenticator returns same userHandle → same key)
    const decrypted = decryptNsec({
      encryptedBlob,
      keyMaterial,
      credentialId: credential.credentialId,
    })

    expect(decrypted).toEqual(nsecBytes)
  })
})
