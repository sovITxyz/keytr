import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import { PRF_SALT } from '../../src/types.js'

const TEST_PUBKEY = bytesToHex(randomBytes(32))

// Stash originals for cleanup
const originalNavigator = globalThis.navigator
const originalCrypto = globalThis.crypto

function makePrfOutput(): Uint8Array {
  return randomBytes(32)
}

function mockCredentialCreate(prfOutput: Uint8Array) {
  const rawId = randomBytes(16)
  return vi.fn().mockResolvedValue({
    type: 'public-key',
    rawId: rawId.buffer.slice(0),
    response: {
      getTransports: () => ['internal', 'hybrid'],
    },
    getClientExtensionResults: () => ({
      prf: {
        enabled: true,
        results: { first: prfOutput.buffer.slice(0) },
      },
    }),
  })
}

function mockCredentialGet(prfOutput: Uint8Array) {
  return vi.fn().mockResolvedValue({
    type: 'public-key',
    rawId: randomBytes(16).buffer.slice(0),
    response: {},
    getClientExtensionResults: () => ({
      prf: {
        results: { first: prfOutput.buffer.slice(0) },
      },
    }),
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

  it('registerPasskey returns credential and PRF output', async () => {
    const prfOutput = makePrfOutput()
    const { create } = setupGlobals({ create: mockCredentialCreate(prfOutput) })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    const result = await registerPasskey({
      userName: 'alice',
      userDisplayName: 'Alice',
      pubkey: TEST_PUBKEY,
    })

    expect(result.credential.prfSupported).toBe(true)
    expect(result.credential.rpId).toBe('keytr.org')
    expect(result.credential.credentialId).toBeInstanceOf(Uint8Array)
    expect(result.credential.credentialIdBase64url).toBe(
      base64url.encode(result.credential.credentialId)
    )
    expect(result.credential.transports).toEqual(['internal', 'hybrid'])
    expect(result.prfOutput).toEqual(prfOutput)
    expect(create).toHaveBeenCalledOnce()
  })

  it('registerPasskey uses custom rpId and timeout', async () => {
    const prfOutput = makePrfOutput()
    const { create } = setupGlobals({ create: mockCredentialCreate(prfOutput) })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    const result = await registerPasskey({
      userName: 'bob',
      userDisplayName: 'Bob',
      pubkey: TEST_PUBKEY,
      rpId: 'custom.example',
      rpName: 'Custom RP',
      timeout: 60000,
    })

    expect(result.credential.rpId).toBe('custom.example')

    // Verify the options passed to navigator.credentials.create
    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    expect(createCall.publicKey?.rp?.id).toBe('custom.example')
    expect(createCall.publicKey?.rp?.name).toBe('Custom RP')
    expect(createCall.publicKey?.timeout).toBe(60000)
  })

  it('registerPasskey throws PrfNotSupportedError when PRF is missing', async () => {
    const rawId = randomBytes(16)
    setupGlobals({
      create: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: { getTransports: () => [] },
        getClientExtensionResults: () => ({}),
      }),
      // Fallback assertion also returns no PRF output
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({}),
      }),
    })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    await expect(
      registerPasskey({ userName: 'eve', userDisplayName: 'Eve', pubkey: TEST_PUBKEY })
    ).rejects.toThrow('PRF output not available')
  })

  it('registerPasskey throws WebAuthnError on null result', async () => {
    setupGlobals({ create: vi.fn().mockResolvedValue(null) })

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    await expect(
      registerPasskey({ userName: 'eve', userDisplayName: 'Eve', pubkey: TEST_PUBKEY })
    ).rejects.toThrow('Credential creation returned null')
  })

  it('authenticatePasskey returns PRF output', async () => {
    const prfOutput = makePrfOutput()
    const credentialId = randomBytes(16)
    setupGlobals({ get: mockCredentialGet(prfOutput) })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')

    const result = await authenticatePasskey({
      credentialId,
      rpId: 'keytr.org',
      transports: ['internal'],
    })

    expect(result).toEqual(prfOutput)
  })

  it('authenticatePasskey uses custom timeout', async () => {
    const prfOutput = makePrfOutput()
    const credentialId = randomBytes(16)
    const { get } = setupGlobals({ get: mockCredentialGet(prfOutput) })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')

    await authenticatePasskey({
      credentialId,
      rpId: 'keytr.org',
      timeout: 30000,
    })

    const getCall = get.mock.calls[0][0] as CredentialRequestOptions
    expect(getCall.publicKey?.timeout).toBe(30000)
  })

  it('authenticatePasskey throws when PRF output is missing', async () => {
    const credentialId = randomBytes(16)
    setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({}),
      }),
    })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')

    await expect(
      authenticatePasskey({ credentialId, rpId: 'keytr.org' })
    ).rejects.toThrow('PRF output not available')
  })

  it('full register → encrypt → authenticate → decrypt roundtrip', async () => {
    const prfOutput = makePrfOutput()

    // Registration
    setupGlobals({
      create: mockCredentialCreate(prfOutput),
      get: mockCredentialGet(prfOutput),
    })

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    const { encryptNsec } = await import('../../src/crypto/encrypt.js')
    const { decryptNsec } = await import('../../src/crypto/decrypt.js')

    // Step 1: Register passkey
    const { credential, prfOutput: regPrf } = await registerPasskey({
      userName: 'alice',
      userDisplayName: 'Alice',
      pubkey: TEST_PUBKEY,
    })

    // Step 2: Encrypt nsec
    const nsecBytes = randomBytes(32)
    const encryptedBlob = encryptNsec({
      nsecBytes,
      prfOutput: regPrf,
      credentialId: credential.credentialId,
    })

    // Step 3: Authenticate (simulates login on new device)
    const authPrf = await authenticatePasskey({
      credentialId: credential.credentialId,
      rpId: credential.rpId,
      transports: credential.transports,
    })

    // Step 4: Decrypt nsec
    const decrypted = decryptNsec({
      encryptedBlob,
      prfOutput: authPrf,
      credentialId: credential.credentialId,
    })

    expect(decrypted).toEqual(nsecBytes)
  })
})
