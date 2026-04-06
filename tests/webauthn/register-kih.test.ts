import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import { MODE_BYTE, USER_ID_SIZE } from '../../src/types.js'

// Bypass cached native refs so test mocks on navigator.credentials take effect
vi.mock('../../src/webauthn/natives.js', () => ({
  nativeCreate: undefined,
  nativeGet: undefined,
}))

const originalNavigator = globalThis.navigator

function mockCredentialCreate() {
  const rawId = randomBytes(16)
  return vi.fn().mockImplementation((options: CredentialCreationOptions) => {
    // Capture the userId that was passed to verify format
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

describe('registerPasskey', () => {
  afterEach(() => {
    restoreGlobals()
    vi.restoreAllMocks()
  })

  it('returns credential and keyMaterial', async () => {
    const { create } = setupGlobals({ create: mockCredentialCreate() })

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
    expect(result.keyMaterial).toBeInstanceOf(Uint8Array)
    expect(result.keyMaterial.length).toBe(32)

    // Only one ceremony — no follow-up assertion needed
    expect(create).toHaveBeenCalledOnce()
  })

  it('passes 33-byte user.id to WebAuthn', async () => {
    const { create } = setupGlobals({ create: mockCredentialCreate() })

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    await registerPasskey({ userName: 'bob', userDisplayName: 'Bob' })

    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    const userId = new Uint8Array(createCall.publicKey!.user.id as ArrayBuffer)
    expect(userId.length).toBe(USER_ID_SIZE)
    expect(userId[0]).toBe(MODE_BYTE)
  })

  it('does not include PRF extension', async () => {
    const { create } = setupGlobals({ create: mockCredentialCreate() })

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    await registerPasskey({ userName: 'carol', userDisplayName: 'Carol' })

    const createCall = create.mock.calls[0][0] as CredentialCreationOptions
    const extensions = createCall.publicKey?.extensions as any
    expect(extensions?.prf).toBeUndefined()
  })

  it('uses custom rpId and timeout', async () => {
    const { create } = setupGlobals({ create: mockCredentialCreate() })

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    await registerPasskey({
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

    const { registerPasskey } = await import('../../src/webauthn/register.js')

    await expect(
      registerPasskey({ userName: 'eve', userDisplayName: 'Eve' })
    ).rejects.toThrow('Credential creation returned null')
  })
})
