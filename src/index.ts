// Types
export type {
  KeytrCredential,
  EncryptedNsecBlob,
  KeytrEventTemplate,
  EncryptOptions,
  DecryptOptions,
  PrfSupportInfo,
  RegisterOptions,
  AuthenticateOptions,
  DiscoverOptions,
  DiscoverResult,
  KeytrBundle,
  KeytrMode,
  UnifiedDiscoverResult,
  KihRegisterOptions,
  KihRegisterResult,
} from './types.js'

export {
  KEYTR_VERSION,
  KEYTR_KIH_VERSION,
  KEYTR_EVENT_KIND,
  DEFAULT_RP_ID,
  DEFAULT_RP_NAME,
  KEYTR_GATEWAYS,
  KIH_KEY_SIZE,
  KIH_USER_ID_SIZE,
  KIH_MODE_BYTE,
  PRF_USER_ID_SIZE,
} from './types.js'

// Errors
export {
  KeytrError,
  PrfNotSupportedError,
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
export { checkPrfSupport } from './webauthn/support.js'
export { registerPasskey } from './webauthn/register.js'
export { registerKihPasskey } from './webauthn/register-kih.js'
export { authenticatePasskey, discoverPasskey, unifiedDiscover } from './webauthn/authenticate.js'
export { generateKihUserId, detectMode, extractKihKey } from './webauthn/kih.js'

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

import type { RegisterOptions, DiscoverOptions, KeytrBundle, KeytrMode } from './types.js'
import { DEFAULT_RP_ID, KEYTR_KIH_VERSION } from './types.js'
import { WebAuthnError, RelayError, KeytrError, PrfNotSupportedError } from './errors.js'
import { registerPasskey } from './webauthn/register.js'
import { registerKihPasskey as _registerKih } from './webauthn/register-kih.js'
import { authenticatePasskey } from './webauthn/authenticate.js'
import { discoverPasskey } from './webauthn/authenticate.js'
import { unifiedDiscover as _unifiedDiscover } from './webauthn/authenticate.js'
import { encryptNsec as _encryptNsec } from './crypto/encrypt.js'
import { decryptNsec as _decryptNsec } from './crypto/decrypt.js'
import { buildKeytrEvent as _buildEvent } from './nostr/event.js'
import { parseKeytrEvent as _parseEvent } from './nostr/event.js'
import { generateNsec as _generateNsec, nsecToNpub as _nsecToNpub, nsecToHexPubkey as _nsecToHexPubkey } from './nostr/keys.js'
import { fetchKeytrEvents as _fetchEvents, fetchKeytrEventByDTag as _fetchByDTag } from './nostr/relay.js'
import { base64url } from '@scure/base'

/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * The pubkey is derived from the generated nsec and stored as WebAuthn user.id
 * to enable discoverable login.
 */
export async function setupKeytr(
  options: Omit<RegisterOptions, 'pubkey'> & { clientName?: string }
): Promise<KeytrBundle & { nsecBytes: Uint8Array; npub: string }> {
  const nsecBytes = _generateNsec()
  const npub = _nsecToNpub(nsecBytes)
  const pubkey = _nsecToHexPubkey(nsecBytes)

  const { credential, prfOutput } = await registerPasskey({ ...options, pubkey })

  try {
    const encryptedBlob = _encryptNsec({
      nsecBytes,
      prfOutput,
      credentialId: credential.credentialId,
    })

    const eventTemplate = _buildEvent({
      credential,
      encryptedBlob,
      clientName: options.clientName,
    })

    return { credential, encryptedBlob, eventTemplate, nsecBytes, npub }
  } finally {
    prfOutput.fill(0)
  }
}

/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 * The pubkey is derived from the provided nsec.
 */
export async function addBackupGateway(
  nsecBytes: Uint8Array,
  options: Omit<RegisterOptions, 'pubkey'> & { clientName?: string }
): Promise<KeytrBundle> {
  const pubkey = _nsecToHexPubkey(nsecBytes)
  const { credential, prfOutput } = await registerPasskey({ ...options, pubkey })

  try {
    const encryptedBlob = _encryptNsec({
      nsecBytes,
      prfOutput,
      credentialId: credential.credentialId,
    })

    const eventTemplate = _buildEvent({
      credential,
      encryptedBlob,
      clientName: options.clientName,
    })

    return { credential, encryptedBlob, eventTemplate }
  } finally {
    prfOutput.fill(0)
  }
}

/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:31777 events for this pubkey. The function tries each
 * event in order — the first passkey the authenticator recognises wins.
 * This works regardless of which gateway the passkey was registered with.
 */
export async function loginWithKeytr(events: {
  kind: number
  content: string
  tags: string[][]
}[]): Promise<{ nsecBytes: Uint8Array; npub: string }> {
  if (events.length === 0) {
    throw new WebAuthnError('No keytr events provided')
  }

  let lastError: Error | undefined

  for (const event of events) {
    const parsed = _parseEvent(event)

    let prfOutput: Uint8Array
    try {
      prfOutput = await authenticatePasskey({
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
        prfOutput,
        credentialId: parsed.credentialId,
      })

      const npub = _nsecToNpub(nsecBytes)
      return { nsecBytes, npub }
    } finally {
      prfOutput.fill(0)
    }
  }

  throw new WebAuthnError(
    `No matching passkey found across ${events.length} event(s): ${lastError?.message ?? 'unknown error'}`
  )
}

/**
 * Discoverable login: browser shows available passkeys, user picks one,
 * we recover the pubkey, fetch events, and decrypt the nsec.
 *
 * No prior knowledge of the user's pubkey or credential ID is needed.
 * Requires passkeys registered with pubkey as user.id (post-discoverable-login update).
 */
export async function discoverAndLogin(
  relays: string[],
  options?: DiscoverOptions
): Promise<{ nsecBytes: Uint8Array; npub: string; pubkey: string }> {
  const { pubkey, prfOutput, credentialId } = await discoverPasskey({
    rpId: options?.rpId ?? DEFAULT_RP_ID,
    timeout: options?.timeout,
  })

  let events
  try {
    events = await _fetchEvents(pubkey, relays)
  } catch (err) {
    prfOutput.fill(0)
    throw err
  }

  if (!events.length) {
    prfOutput.fill(0)
    throw new RelayError('No keytr events found for this pubkey')
  }

  const credentialIdB64 = base64url.encode(credentialId)
  const matching = events.find(e => {
    const dTag = e.tags.find((t: string[]) => t[0] === 'd')?.[1]
    return dTag === credentialIdB64
  })

  if (!matching) {
    prfOutput.fill(0)
    throw new KeytrError(
      `No event matches credential ${credentialIdB64} — ` +
      `passkey may have been registered before discoverable login was enabled`
    )
  }

  try {
    const parsed = _parseEvent(matching)
    const nsecBytes = _decryptNsec({
      encryptedBlob: parsed.encryptedBlob,
      prfOutput,
      credentialId,
    })

    const npub = _nsecToNpub(nsecBytes)
    return { nsecBytes, npub, pubkey }
  } finally {
    prfOutput.fill(0)
  }
}

// ---- Unified API (PRF-first with KiH fallback) ----

/** Options for the unified setup flow */
export interface SetupOptions {
  rpId?: string
  rpName?: string
  userName: string
  userDisplayName: string
  clientName?: string
  timeout?: number
}

/** Result of the unified setup flow */
export interface SetupResult extends KeytrBundle {
  nsecBytes: Uint8Array
  npub: string
  mode: KeytrMode
}

/**
 * Unified setup: tries PRF registration first, falls back to KiH if PRF fails.
 *
 * PRF mode stores the pubkey in user.id (32 bytes) and relies on the
 * authenticator's PRF extension for key derivation.
 *
 * KiH mode stores a random key in user.id (33 bytes, 0x03 prefix) and
 * works with any authenticator including password manager extensions.
 */
export async function setup(options: SetupOptions): Promise<SetupResult> {
  const nsecBytes = _generateNsec()
  const npub = _nsecToNpub(nsecBytes)
  const pubkey = _nsecToHexPubkey(nsecBytes)

  // Try PRF first
  try {
    const { credential, prfOutput } = await registerPasskey({
      rpId: options.rpId,
      rpName: options.rpName,
      userName: options.userName,
      userDisplayName: options.userDisplayName,
      pubkey,
      timeout: options.timeout,
    })

    try {
      const encryptedBlob = _encryptNsec({
        nsecBytes,
        prfOutput,
        credentialId: credential.credentialId,
      })

      const eventTemplate = _buildEvent({
        credential,
        encryptedBlob,
        clientName: options.clientName,
      })

      return { credential, encryptedBlob, eventTemplate, nsecBytes, npub, mode: 'prf' }
    } finally {
      prfOutput.fill(0)
    }
  } catch (err) {
    // Only fall back to KiH if PRF specifically failed
    if (!(err instanceof PrfNotSupportedError)) throw err
  }

  // KiH fallback
  const { credential, handleKey } = await _registerKih({
    rpId: options.rpId,
    rpName: options.rpName,
    userName: options.userName,
    userDisplayName: options.userDisplayName,
    timeout: options.timeout,
  })

  try {
    const encryptedBlob = _encryptNsec({
      nsecBytes,
      prfOutput: handleKey,
      credentialId: credential.credentialId,
      aadVersion: KEYTR_KIH_VERSION,
    })

    const eventTemplate = _buildEvent({
      credential,
      encryptedBlob,
      clientName: options.clientName,
      version: String(KEYTR_KIH_VERSION),
    })

    return { credential, encryptedBlob, eventTemplate, nsecBytes, npub, mode: 'kih' }
  } finally {
    handleKey.fill(0)
  }
}

/** Result of the unified discover flow */
export interface DiscoverLoginResult {
  nsecBytes: Uint8Array
  npub: string
  pubkey: string
  mode: KeytrMode
}

/**
 * Unified discoverable login: auto-detects PRF vs KiH from userHandle length.
 *
 * 1. Discovery assertion (1 biometric prompt for both modes)
 * 2. If PRF: step-2 targeted assertion for PRF output, then query by pubkey
 * 3. If KiH: extract key from userHandle, query relay by #d tag
 * 4. Decrypt nsec, derive pubkey, verify against event.pubkey
 */
export async function discover(
  relays: string[],
  options?: DiscoverOptions
): Promise<DiscoverLoginResult> {
  const result = await _unifiedDiscover({
    rpId: options?.rpId ?? DEFAULT_RP_ID,
    timeout: options?.timeout,
  })

  const credentialIdB64 = base64url.encode(result.credentialId)

  let event: { kind: number; content: string; tags: string[][]; pubkey?: string } | null = null

  if (result.mode === 'prf' && result.pubkey) {
    // PRF path: fetch by pubkey, find matching credential
    const events = await _fetchEvents(result.pubkey, relays)
    event = events.find(e => {
      const dTag = e.tags.find((t: string[]) => t[0] === 'd')?.[1]
      return dTag === credentialIdB64
    }) ?? null
  } else {
    // KiH path: fetch by d-tag (no pubkey available)
    event = await _fetchByDTag(credentialIdB64, relays)
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
      prfOutput: result.keyMaterial,
      credentialId: result.credentialId,
      aadVersion: result.aadVersion,
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

    return { nsecBytes, npub, pubkey, mode: result.mode }
  } finally {
    result.keyMaterial.fill(0)
  }
}
