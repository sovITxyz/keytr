/** Blob version for the encrypted nsec format */
export const KEYTR_VERSION = 1

/** Nostr event kind for passkey-encrypted private keys */
export const KEYTR_EVENT_KIND = 30079

/** PRF salt used during WebAuthn ceremonies */
export const PRF_SALT = new TextEncoder().encode('keytr-v1')

/** HKDF info string for key derivation */
export const HKDF_INFO = 'keytr nsec encryption v1'

/**
 * Well-known passkey gateways for cross-client compatibility.
 * Any domain can host a .well-known/webauthn file and become a gateway.
 * Clients can also use their own domain as a standalone rpId.
 *
 * The gateway model is federated: multiple independent domains can each
 * authorize their own set of origins. Users encrypt their nsec once per
 * gateway (or standalone rpId), producing separate kind:30079 events.
 * Any client sharing the same rpId can decrypt the matching event.
 */
export const DEFAULT_RP_ID = 'keytr.org'
export const DEFAULT_RP_NAME = 'keytr'

/**
 * Well-known passkey gateways.
 * The primary gateway is used during initial setup (1 biometric prompt).
 * Additional gateways can be registered later via addBackupGateway().
 */
export const KEYTR_GATEWAYS = ['keytr.org', 'nostkey.org'] as const

/** Result of passkey registration with PRF enabled */
export interface KeytrCredential {
  credentialId: Uint8Array
  credentialIdBase64url: string
  rpId: string
  transports: AuthenticatorTransport[]
  prfSupported: boolean
}

/** The encrypted nsec blob (parsed binary structure) */
export interface EncryptedNsecBlob {
  version: number       // 1 byte
  iv: Uint8Array         // 12 bytes
  hkdfSalt: Uint8Array   // 32 bytes
  ciphertext: Uint8Array // 48 bytes (32-byte nsec + 16-byte GCM tag)
}

/** A kind:30079 event payload (before signing) */
export interface KeytrEventTemplate {
  kind: typeof KEYTR_EVENT_KIND
  content: string  // base64-encoded EncryptedNsecBlob
  tags: string[][]
  created_at: number
}

/** Options for encrypting an nsec */
export interface EncryptOptions {
  nsecBytes: Uint8Array       // 32-byte raw private key
  prfOutput: Uint8Array       // 32-byte PRF result from authenticator
  credentialId: Uint8Array    // credential ID for AAD binding
}

/** Options for decrypting an nsec */
export interface DecryptOptions {
  encryptedBlob: string       // base64-encoded blob from event content
  prfOutput: Uint8Array       // 32-byte PRF result from authenticator
  credentialId: Uint8Array    // credential ID for AAD verification
}

/** PRF support detection result */
export interface PrfSupportInfo {
  supported: boolean
  platformAuthenticator: boolean
  reason?: string
}

/** Passkey registration options */
export interface RegisterOptions {
  /**
   * Relying Party ID. This determines which clients can decrypt.
   *
   * - Use a gateway domain (e.g. "keytr.org") for cross-client compatibility
   *   with all clients authorized by that gateway.
   * - Use your own domain for standalone mode (only your client can decrypt).
   * - Register multiple rpIds for maximum portability.
   *
   * Defaults to "keytr.org".
   */
  rpId?: string
  /** Relying Party display name. Defaults to "keytr". */
  rpName?: string
  userName: string
  userDisplayName: string
  /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
  timeout?: number
}

/** Passkey authentication options for decryption */
export interface AuthenticateOptions {
  credentialId: Uint8Array
  rpId: string
  transports?: AuthenticatorTransport[]
  /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
  timeout?: number
}

/** Full encrypt-and-wrap result */
export interface KeytrBundle {
  credential: KeytrCredential
  encryptedBlob: string
  eventTemplate: KeytrEventTemplate
}
