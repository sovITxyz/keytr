import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import { KIH_MODE_BYTE, KIH_USER_ID_SIZE } from '../../src/types.js'

const originalNavigator = globalThis.navigator

function mockKihCredentialCreate() {
  const rawId = randomBytes(16)
  return vi.fn().mockImplementation((options: CredentialCreationOptions) => {
    // Capture the userId that was passed to verify KiH format
    const userId = new Uint8Array(options.publicKey!.user.id as ArrayBuffer)
    return Promise.resolve({
      type: 'public-key',
      rawId: rawId.buffer.slice(0),
      response: {
        getTransports: () => ['internal', 'hybrid'],
      },
      getClientExtensionResults: () => ({}),
      _testUserId: userId, // stash for assertions
    })
  })
}

function setupGlobals(overrides?: { create?: ReturnType<typeof vi.fn> }) {
  const create = overrides?.create ?? vi.fn()

  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: { create, get: vi.fn() } },
    configurable: true,
  })

  if (!globalThis.crypto?.getRandomValues) {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        getRandomValues: (arr: Uint8Array) => {
          arr.set(randomBytes(arr.length))
          return arr
        },
      },
      configurable: true,
    })
  }

  return { create }
}

function restoreGlobals() {
  Object.defineProperty(globalThis, 'navigator', {
    value: originalNavigator,
    configurable: true,
  })
}

describe('registerKihPasskey', () => {
  afterEach(() => {
    restoreGlobals()
    vi.restoreAllMocks()
  })

  it('returns credential and handleKey without PRF', async () => {
    const { create } = setupGlobals({ create: mockKihCredentialCreate() })

    const { registerKihPasskey } = await import('../../src/webauthn/register-kih.js')

    const result = await registerKihPasskey({
      userName: 'alice',
      userDisplayName: 'Alice',
    })

    expect(result.credential.prfSupported).toBe(false)
    expect(result.credential.rpId).toBe('keytr.org')
    expect(result.credential.credentialId).toBeInstanceOf(Uint8Array)
    expect(result.credential.credentialIdBase64url).toBe(
      base64url.encode(result.credential.credentialId)
    )
    expect(result.handleKey).toBeInstanceOf(Uint8Array)
    expect(result.handleKey.length).toBe(32)

    // Only one ceremony — no follow-up assertion
    expect(create).toHaveBeenCalledOnce()
  })

  it('passes 33-byte KiH user.id to WebAuthn', async () => {
    const { create } = setupGlobals({ create: mockKihCredentialCreate() })

    const { registerKihPasskey } = await import('../../src/webauthn/register-kih.js')
    await registerKihPasskey({ userName: 'bob', userDisplayName: 'Bob' })

    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    const userId = new Uint8Array(createCall.publicKey!.user.id as ArrayBuffer)
    expect(userId.length).toBe(KIH_USER_ID_SIZE)
    expect(userId[0]).toBe(KIH_MODE_BYTE)
  })

  it('does not include PRF extension', async () => {
    const { create } = setupGlobals({ create: mockKihCredentialCreate() })

    const { registerKihPasskey } = await import('../../src/webauthn/register-kih.js')
    await registerKihPasskey({ userName: 'carol', userDisplayName: 'Carol' })

    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    const extensions = createCall.publicKey?.extensions as any
    expect(extensions?.prf).toBeUndefined()
  })

  it('uses custom rpId and timeout', async () => {
    const { create } = setupGlobals({ create: mockKihCredentialCreate() })

    const { registerKihPasskey } = await import('../../src/webauthn/register-kih.js')
    await registerKihPasskey({
      userName: 'dave',
      userDisplayName: 'Dave',
      rpId: 'custom.example',
      rpName: 'Custom',
      timeout: 60000,
    })

    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    expect(createCall.publicKey?.rp?.id).toBe('custom.example')
    expect(createCall.publicKey?.rp?.name).toBe('Custom')
    expect(createCall.publicKey?.timeout).toBe(60000)
  })

  it('throws WebAuthnError on null result', async () => {
    setupGlobals({ create: vi.fn().mockResolvedValue(null) })

    const { registerKihPasskey } = await import('../../src/webauthn/register-kih.js')

    await expect(
      registerKihPasskey({ userName: 'eve', userDisplayName: 'Eve' })
    ).rejects.toThrow('Credential creation returned null')
  })
})
