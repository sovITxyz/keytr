/** AAD version byte for PRF mode (original) */
export const KEYTR_VERSION = 1

/** AAD version byte for Key-in-Handle (KiH) mode */
export const KEYTR_KIH_VERSION = 3

/** Size of the random encryption key embedded in KiH user.id */
export const KIH_KEY_SIZE = 32

/** Total size of KiH user.id: mode byte (0x03) + 32-byte key */
export const KIH_USER_ID_SIZE = 33

/** Mode prefix byte written as user.id[0] in KiH mode */
export const KIH_MODE_BYTE = 0x03

/** PRF mode user.id size (32-byte pubkey) */
export const PRF_USER_ID_SIZE = 32

/** Nostr event kind for passkey-encrypted private keys */
export const KEYTR_EVENT_KIND = 31777

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
 * gateway (or standalone rpId), producing separate kind:31777 events.
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
  /** Whether the credential is eligible for multi-device sync (BE flag from authenticatorData) */
  backupEligible?: boolean
  /** Whether the credential is currently backed up / synced (BS flag from authenticatorData) */
  backupState?: boolean
}

/** The encrypted nsec blob (parsed binary structure) */
export interface EncryptedNsecBlob {
  version: number       // 1 byte
  iv: Uint8Array         // 12 bytes
  hkdfSalt: Uint8Array   // 32 bytes
  ciphertext: Uint8Array // 48 bytes (32-byte nsec + 16-byte GCM tag)
}

/** A kind:31777 event payload (before signing) */
export interface KeytrEventTemplate {
  kind: typeof KEYTR_EVENT_KIND
  content: string  // base64-encoded EncryptedNsecBlob
  tags: string[][]
  created_at: number
}

/** Options for encrypting an nsec */
export interface EncryptOptions {
  nsecBytes: Uint8Array       // 32-byte raw private key
  prfOutput: Uint8Array       // 32-byte PRF result or KiH handle key
  credentialId: Uint8Array    // credential ID for AAD binding
  /** AAD version byte. Defaults to KEYTR_VERSION (1) for PRF, use KEYTR_KIH_VERSION (3) for KiH. */
  aadVersion?: number
}

/** Options for decrypting an nsec */
export interface DecryptOptions {
  encryptedBlob: string       // base64-encoded blob from event content
  prfOutput: Uint8Array       // 32-byte PRF result or KiH handle key
  credentialId: Uint8Array    // credential ID for AAD verification
  /** AAD version byte. Defaults to KEYTR_VERSION (1) for PRF, use KEYTR_KIH_VERSION (3) for KiH. */
  aadVersion?: number
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
  /**
   * Hex-encoded 32-byte Nostr public key, stored as WebAuthn user.id.
   * This enables discoverable credential login — the browser returns
   * the pubkey via userHandle when the user picks a passkey.
   */
  pubkey: string
  /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
  timeout?: number
  /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
  hints?: string[]
}

/** Options for discoverable passkey authentication (no prior pubkey needed) */
export interface DiscoverOptions {
  rpId?: string
  /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
  timeout?: number
  /**
   * Credential mediation requirement. Set to 'conditional' for passkey autofill
   * (requires <input autocomplete="webauthn"> in the DOM). Defaults to 'optional' (modal picker).
   */
  mediation?: 'silent' | 'optional' | 'conditional' | 'required'
  /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
  hints?: string[]
}

/** Result of discoverable passkey authentication (PRF mode) */
export interface DiscoverResult {
  /** Hex-encoded Nostr public key recovered from WebAuthn userHandle */
  pubkey: string
  /** 32-byte PRF output for key derivation */
  prfOutput: Uint8Array
  /** Raw credential ID */
  credentialId: Uint8Array
}

/** Encryption mode: PRF (authenticator-derived key) or KiH (key-in-handle) */
export type KeytrMode = 'prf' | 'kih'

/** Result of unified discoverable authentication (auto-detects PRF vs KiH) */
export interface UnifiedDiscoverResult {
  /** Detected mode based on userHandle length */
  mode: KeytrMode
  /** 32-byte key material (PRF output or KiH handle key) */
  keyMaterial: Uint8Array
  /** Raw credential ID */
  credentialId: Uint8Array
  /** AAD version byte for this mode */
  aadVersion: number
  /** Hex-encoded pubkey — only available in PRF mode (from userHandle) */
  pubkey?: string
}

/** Options for KiH passkey registration (no PRF extension needed) */
export interface KihRegisterOptions {
  rpId?: string
  rpName?: string
  userName: string
  userDisplayName: string
  /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
  timeout?: number
  /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
  hints?: string[]
}

/** Result of KiH passkey registration */
export interface KihRegisterResult {
  credential: KeytrCredential
  /** 32-byte random key extracted from user.id for encryption */
  handleKey: Uint8Array
}

/** Passkey authentication options for decryption */
export interface AuthenticateOptions {
  credentialId: Uint8Array
  rpId: string
  transports?: AuthenticatorTransport[]
  /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
  timeout?: number
  /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
  hints?: string[]
}

/** Full encrypt-and-wrap result */
export interface KeytrBundle {
  credential: KeytrCredential
  encryptedBlob: string
  eventTemplate: KeytrEventTemplate
}

/** Browser WebAuthn capability report from getClientCapabilities() */
export interface WebAuthnCapabilities {
  /** Whether WebAuthn is available in this environment */
  webauthn: boolean
  /** Whether a platform authenticator is available */
  platformAuthenticator: boolean
  /** PRF extension support (null = unknown, requires credential creation to confirm) */
  prf: boolean | null
  /** Whether conditional mediation (passkey autofill) is supported */
  conditionalMediation: boolean
  /** Whether Related Origin Requests are supported (cross-domain passkey use) */
  relatedOrigins: boolean
  /** Whether the WebAuthn Signal API is supported (credential lifecycle management) */
  signalApi: boolean
}
