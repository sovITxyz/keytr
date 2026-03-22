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
  KeytrBundle,
} from './types.js'

export { KEYTR_VERSION, KEYTR_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME } from './types.js'

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
export { encryptNsec } from './crypto/encrypt.js'
export { decryptNsec } from './crypto/decrypt.js'
export { deriveKey } from './crypto/kdf.js'
export { serializeBlob, deserializeBlob } from './crypto/blob.js'

// WebAuthn
export { checkPrfSupport } from './webauthn/support.js'
export { registerPasskey } from './webauthn/register.js'
export { authenticatePasskey } from './webauthn/authenticate.js'

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
export { buildKeytrEvent, parseKeytrEvent } from './nostr/event.js'
export { publishKeytrEvent, fetchKeytrEvents } from './nostr/relay.js'

// Password fallback
export { encryptNsecWithPassword, decryptNsecFromPassword } from './fallback/password.js'

// ---- High-level convenience functions ----

import type { RegisterOptions, KeytrBundle } from './types.js'
import { registerPasskey } from './webauthn/register.js'
import { authenticatePasskey } from './webauthn/authenticate.js'
import { encryptNsec as _encryptNsec } from './crypto/encrypt.js'
import { decryptNsec as _decryptNsec } from './crypto/decrypt.js'
import { buildKeytrEvent as _buildEvent } from './nostr/event.js'
import { parseKeytrEvent as _parseEvent } from './nostr/event.js'
import { generateNsec as _generateNsec, nsecToNpub as _nsecToNpub } from './nostr/keys.js'

/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 */
export async function setupKeytr(
  options: RegisterOptions & { clientName?: string }
): Promise<KeytrBundle & { nsecBytes: Uint8Array; npub: string }> {
  const nsecBytes = _generateNsec()
  const npub = _nsecToNpub(nsecBytes)

  const { credential, prfOutput } = await registerPasskey(options)

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
 * Full login flow: authenticate with passkey, decrypt nsec from event.
 *
 * This is the "login on new device" flow.
 */
export async function loginWithKeytr(event: {
  kind: number
  content: string
  tags: string[][]
}): Promise<{ nsecBytes: Uint8Array; npub: string }> {
  const parsed = _parseEvent(event)

  const prfOutput = await authenticatePasskey({
    credentialId: parsed.credentialId,
    rpId: parsed.rpId,
    transports: parsed.transports as AuthenticatorTransport[],
  })

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
