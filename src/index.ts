// Types
export type {
  KeytrCredential,
  EncryptedNsecBlob,
  KeytrEventTemplate,
  EncryptOptions,
  DecryptOptions,
  RegisterOptions,
  RegisterResult,
  AuthenticateOptions,
  DiscoverOptions,
  DiscoverResult,
  KeytrBundle,
  KeyStrategy,
  WebAuthnCapabilities,
} from './types.js'

export {
  KEYTR_VERSION,
  BLOB_VERSION,
  KEYTR_EVENT_KIND,
  DEFAULT_RP_ID,
  DEFAULT_RP_NAME,
  KEYTR_GATEWAYS,
  KEY_SIZE,
  USER_ID_SIZE,
  MODE_BYTE,
} from './types.js'

// Errors
export {
  KeytrError,
  EncryptionError,
  DecryptionError,
  BlobParseError,
  WebAuthnError,
  RelayError,
} from './errors.js'

// Crypto
export { encryptNsec, buildAad } from './crypto/encrypt.js'
export { decryptNsec } from './crypto/decrypt.js'
export { deriveKey } from './crypto/kdf.js'
export { serializeBlob, deserializeBlob } from './crypto/blob.js'

// WebAuthn
export { checkCapabilities, ensureBrowser } from './webauthn/support.js'
export { registerPasskey } from './webauthn/register.js'
export { authenticatePasskey, discoverPasskey } from './webauthn/authenticate.js'
export { generateUserId, extractKey } from './webauthn/kih.js'
export { parseBackupFlags } from './webauthn/flags.js'
export {
  signalUnknownCredential,
  signalAllAcceptedCredentialIds,
  signalCurrentUserDetails,
} from './webauthn/signal.js'

// Nostr
export {
  generateNsec,
  nsecToPublicKey,
  encodeNsec,
  decodeNsec,
  encodeNpub,
  decodeNpub,
  nsecToNpub,
  nsecToHexPubkey,
} from './nostr/keys.js'
export { buildKeytrEvent, parseKeytrEvent, type ParsedKeytrEvent } from './nostr/event.js'
export { publishKeytrEvent, fetchKeytrEvents, fetchKeytrEventByDTag, type RelayOptions } from './nostr/relay.js'

// Password fallback — DISABLED
// Password-encrypted nsec is not safe to publish to relays. An attacker can
// fetch the event and brute-force the password offline. This will be re-enabled
// once a safe UX is designed (local-only storage, entropy enforcement, user warnings).
// The code is retained in src/fallback/password.ts and tested.
// export { encryptNsecWithPassword, decryptNsecFromPassword } from './fallback/password.js'

// ---- High-level convenience functions ----

import type { RegisterOptions, DiscoverOptions, KeytrBundle, KeyStrategy } from './types.js'
import type { RelayOptions } from './nostr/relay.js'
import { DEFAULT_RP_ID, KEYTR_VERSION } from './types.js'
import { WebAuthnError, RelayError, KeytrError } from './errors.js'
import { registerPasskey } from './webauthn/register.js'
import { authenticatePasskey } from './webauthn/authenticate.js'
import { discoverPasskey as _discoverPasskey } from './webauthn/authenticate.js'
import { encryptNsec as _encryptNsec } from './crypto/encrypt.js'
import { decryptNsec as _decryptNsec } from './crypto/decrypt.js'
import { buildKeytrEvent as _buildEvent } from './nostr/event.js'
import { parseKeytrEvent as _parseEvent } from './nostr/event.js'
import { generateNsec as _generateNsec, nsecToNpub as _nsecToNpub, nsecToHexPubkey as _nsecToHexPubkey } from './nostr/keys.js'
import { fetchKeytrEvents as _fetchByPubkey, fetchKeytrEventByDTag as _fetchByDTag } from './nostr/relay.js'
import { base64url } from '@scure/base'

/** Built-in KiH (Key-in-Handle) strategy — the default */
export const kihStrategy: KeyStrategy = {
  version: KEYTR_VERSION,
  register: registerPasskey,
  authenticate: authenticatePasskey,
  discover: _discoverPasskey,
}

/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * Single biometric prompt — the encryption key is embedded in the passkey's user.id.
 */
export async function setupKeytr(
  options: RegisterOptions & { clientName?: string; strategy?: KeyStrategy }
): Promise<KeytrBundle & { nsecBytes: Uint8Array; npub: string }> {
  const strategy = options.strategy ?? kihStrategy
  const nsecBytes = _generateNsec()
  const npub = _nsecToNpub(nsecBytes)

  const { credential, keyMaterial } = await strategy.register(options)

  try {
    const encryptedBlob = _encryptNsec({
      nsecBytes,
      keyMaterial,
      credentialId: credential.credentialId,
      version: strategy.version,
    })

    const eventTemplate = _buildEvent({
      credential,
      encryptedBlob,
      clientName: options.clientName,
      version: strategy.version,
    })

    return { credential, encryptedBlob, eventTemplate, nsecBytes, npub }
  } finally {
    keyMaterial.fill(0)
  }
}

/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 */
export async function addBackupGateway(
  nsecBytes: Uint8Array,
  options: RegisterOptions & { clientName?: string; strategy?: KeyStrategy }
): Promise<KeytrBundle> {
  const strategy = options.strategy ?? kihStrategy
  const { credential, keyMaterial } = await strategy.register(options)

  try {
    const encryptedBlob = _encryptNsec({
      nsecBytes,
      keyMaterial,
      credentialId: credential.credentialId,
      version: strategy.version,
    })

    const eventTemplate = _buildEvent({
      credential,
      encryptedBlob,
      clientName: options.clientName,
      version: strategy.version,
    })

    return { credential, encryptedBlob, eventTemplate }
  } finally {
    keyMaterial.fill(0)
  }
}

/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:31777 events for this user. The function tries each
 * event in order — the first passkey the authenticator recognises wins.
 * The encryption key is extracted from the passkey's userHandle.
 */
export async function loginWithKeytr(events: {
  kind: number
  content: string
  tags: string[][]
}[], strategy?: KeyStrategy): Promise<{ nsecBytes: Uint8Array; npub: string }> {
  if (events.length === 0) {
    throw new WebAuthnError('No keytr events provided')
  }

  const strat = strategy ?? kihStrategy
  let lastError: Error | undefined

  for (const event of events) {
    const parsed = _parseEvent(event)

    let keyMaterial: Uint8Array
    try {
      keyMaterial = await strat.authenticate({
        credentialId: parsed.credentialId,
        rpId: parsed.rpId,
        transports: parsed.transports as AuthenticatorTransport[],
      })
    } catch (err) {
      lastError = err as Error
      continue
    }

    try {
      const nsecBytes = _decryptNsec({
        encryptedBlob: parsed.encryptedBlob,
        keyMaterial,
        credentialId: parsed.credentialId,
        version: strat.version,
      })

      const npub = _nsecToNpub(nsecBytes)
      return { nsecBytes, npub }
    } finally {
      keyMaterial.fill(0)
    }
  }

  throw new WebAuthnError(
    `No matching passkey found across ${events.length} event(s): ${lastError?.message ?? 'unknown error'}`
  )
}

/** Options for the unified setup flow */
export interface SetupOptions {
  rpId?: string
  rpName?: string
  userName: string
  userDisplayName: string
  clientName?: string
  timeout?: number
  /** WebAuthn Level 3 hints to guide authenticator selection */
  hints?: string[]
  /** Key derivation strategy. Defaults to kihStrategy (Key-in-Handle). */
  strategy?: KeyStrategy
}

/** Result of the unified setup flow */
export interface SetupResult extends KeytrBundle {
  nsecBytes: Uint8Array
  npub: string
}

/**
 * Setup: generate nsec, register passkey, encrypt, build event.
 *
 * The encryption key is embedded in the passkey's user.id (33 bytes, 0x03 prefix).
 * Works with all authenticators including password manager extensions.
 * Single biometric prompt.
 */
export async function setup(options: SetupOptions): Promise<SetupResult> {
  const strategy = options.strategy ?? kihStrategy
  const nsecBytes = _generateNsec()
  const npub = _nsecToNpub(nsecBytes)

  const { credential, keyMaterial } = await strategy.register({
    rpId: options.rpId,
    rpName: options.rpName,
    userName: options.userName,
    userDisplayName: options.userDisplayName,
    timeout: options.timeout,
    hints: options.hints,
  })

  try {
    const encryptedBlob = _encryptNsec({
      nsecBytes,
      keyMaterial,
      credentialId: credential.credentialId,
      version: strategy.version,
    })

    const eventTemplate = _buildEvent({
      credential,
      encryptedBlob,
      clientName: options.clientName,
      version: strategy.version,
    })

    return { credential, encryptedBlob, eventTemplate, nsecBytes, npub }
  } finally {
    keyMaterial.fill(0)
  }
}

/** Result of the discover flow */
export interface DiscoverLoginResult {
  nsecBytes: Uint8Array
  npub: string
  pubkey: string
}

/**
 * Discoverable login: browser shows available passkeys, user picks one,
 * we extract the encryption key from userHandle, fetch the event, and decrypt.
 *
 * Single biometric prompt. No prior knowledge of the user needed.
 */
export async function discover(
  relays: string[],
  options?: DiscoverOptions & { relayOptions?: RelayOptions; strategy?: KeyStrategy }
): Promise<DiscoverLoginResult> {
  const strategy = options?.strategy ?? kihStrategy
  const discoverOpts: DiscoverOptions = { rpId: options?.rpId ?? DEFAULT_RP_ID }
  if (options?.timeout) discoverOpts.timeout = options.timeout
  if (options?.mediation) discoverOpts.mediation = options.mediation
  if (options?.hints?.length) discoverOpts.hints = options.hints
  const result = await strategy.discover(discoverOpts)

  const credentialIdB64 = base64url.encode(result.credentialId)

  // PRF strategy returns pubkey — fetch events by author then match credential
  // KiH strategy returns no pubkey — fetch directly by d-tag
  let event: { kind: number; content: string; tags: string[][]; pubkey?: string } | null
  if (result.pubkey) {
    const events = await _fetchByPubkey(result.pubkey, relays, options?.relayOptions)
    event = events.find(e => e.tags.some(t => t[0] === 'd' && t[1] === credentialIdB64)) ?? null
  } else {
    event = await _fetchByDTag(credentialIdB64, relays, options?.relayOptions)
  }

  if (!event) {
    result.keyMaterial.fill(0)
    throw new KeytrError(
      `No event matches credential ${credentialIdB64}`
    )
  }

  try {
    const parsed = _parseEvent(event)
    const nsecBytes = _decryptNsec({
      encryptedBlob: parsed.encryptedBlob,
      keyMaterial: result.keyMaterial,
      credentialId: result.credentialId,
      version: strategy.version,
    })

    const pubkey = _nsecToHexPubkey(nsecBytes)
    const npub = _nsecToNpub(nsecBytes)

    // Verify pubkey matches event author (integrity check)
    if ('pubkey' in event && event.pubkey && event.pubkey !== pubkey) {
      nsecBytes.fill(0)
      throw new KeytrError(
        'Decrypted nsec does not match event author pubkey — possible tampering'
      )
    }

    return { nsecBytes, npub, pubkey }
  } finally {
    result.keyMaterial.fill(0)
  }
}
