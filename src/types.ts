/** Blob version for the encrypted nsec format */
export const NOSTKEY_VERSION = 1

/** Nostr event kind for passkey-encrypted private keys */
export const NOSTKEY_EVENT_KIND = 30079

/** PRF salt used during WebAuthn ceremonies */
export const PRF_SALT = new TextEncoder().encode('nostkey-v1')

/** HKDF info string for key derivation */
export const HKDF_INFO = 'nostkey nsec encryption v1'

/**
 * Default Relying Party ID for cross-client compatibility.
 * All Nostr clients using nostkey should register passkeys against this rpId.
 * The nostkey.org domain hosts a .well-known/webauthn file listing authorized origins
 * via the Related Origin Requests spec, so any participating client can use passkeys
 * registered under this rpId.
 */
export const DEFAULT_RP_ID = 'nostkey.org'
export const DEFAULT_RP_NAME = 'nostkey'

/** Result of passkey registration with PRF enabled */
export interface NostkeyCredential {
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
export interface NostkeyEventTemplate {
  kind: typeof NOSTKEY_EVENT_KIND
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
  /** Relying Party ID. Defaults to nostkey.org for cross-client compatibility. */
  rpId?: string
  /** Relying Party display name. Defaults to "nostkey". */
  rpName?: string
  userName: string
  userDisplayName: string
}

/** Passkey authentication options for decryption */
export interface AuthenticateOptions {
  credentialId: Uint8Array
  rpId: string
  transports?: AuthenticatorTransport[]
}

/** Full encrypt-and-wrap result */
export interface NostkeyBundle {
  credential: NostkeyCredential
  encryptedBlob: string
  eventTemplate: NostkeyEventTemplate
}
