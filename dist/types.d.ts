/** Blob binary format version (layout: version(1) | iv(12) | salt(32) | ct(48)) */
export declare const BLOB_VERSION = 1;
/** Protocol / AAD version for events and encryption */
export declare const KEYTR_VERSION = 3;
/** Size of the random encryption key embedded in user.id */
export declare const KEY_SIZE = 32;
/** Total size of user.id: mode byte (0x03) + 32-byte key */
export declare const USER_ID_SIZE = 33;
/** Mode prefix byte written as user.id[0] */
export declare const MODE_BYTE = 3;
/** Nostr event kind for passkey-encrypted private keys */
export declare const KEYTR_EVENT_KIND = 31777;
/** HKDF info string for key derivation */
export declare const HKDF_INFO = "keytr nsec encryption v1";
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
export declare const DEFAULT_RP_ID = "keytr.org";
export declare const DEFAULT_RP_NAME = "keytr";
/**
 * Well-known passkey gateways.
 * The primary gateway is used during initial setup (1 biometric prompt).
 * Additional gateways can be registered later via addBackupGateway().
 */
export declare const KEYTR_GATEWAYS: readonly ["keytr.org", "nostkey.org"];
/** Result of passkey registration */
export interface KeytrCredential {
    credentialId: Uint8Array;
    credentialIdBase64url: string;
    rpId: string;
    transports: AuthenticatorTransport[];
    /** Whether the credential is eligible for multi-device sync (BE flag from authenticatorData) */
    backupEligible?: boolean;
    /** Whether the credential is currently backed up / synced (BS flag from authenticatorData) */
    backupState?: boolean;
}
/** The encrypted nsec blob (parsed binary structure) */
export interface EncryptedNsecBlob {
    version: number;
    iv: Uint8Array;
    hkdfSalt: Uint8Array;
    ciphertext: Uint8Array;
}
/** A kind:31777 event payload (before signing) */
export interface KeytrEventTemplate {
    kind: typeof KEYTR_EVENT_KIND;
    content: string;
    tags: string[][];
    created_at: number;
}
/** Options for encrypting an nsec */
export interface EncryptOptions {
    nsecBytes: Uint8Array;
    keyMaterial: Uint8Array;
    credentialId: Uint8Array;
    /** AAD version byte. Defaults to KEYTR_VERSION (3). Strategies may override. */
    version?: number;
}
/** Options for decrypting an nsec */
export interface DecryptOptions {
    encryptedBlob: string;
    keyMaterial: Uint8Array;
    credentialId: Uint8Array;
    /** AAD version byte. Defaults to KEYTR_VERSION (3). Must match the version used during encryption. */
    version?: number;
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
    rpId?: string;
    /** Relying Party display name. Defaults to "keytr". */
    rpName?: string;
    userName: string;
    userDisplayName: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
    /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
    hints?: string[];
}
/** Result of passkey registration */
export interface RegisterResult {
    credential: KeytrCredential;
    /** 32-byte random key extracted from user.id for encryption */
    keyMaterial: Uint8Array;
}
/** Options for discoverable passkey authentication (no prior credential needed) */
export interface DiscoverOptions {
    rpId?: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
    /**
     * Credential mediation requirement. Set to 'conditional' for passkey autofill
     * (requires <input autocomplete="webauthn"> in the DOM). Defaults to 'optional' (modal picker).
     */
    mediation?: 'silent' | 'optional' | 'conditional' | 'required';
    /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
    hints?: string[];
}
/** Result of discoverable passkey authentication */
export interface DiscoverResult {
    /** 32-byte encryption key extracted from userHandle */
    keyMaterial: Uint8Array;
    /** Raw credential ID */
    credentialId: Uint8Array;
    /** Hex public key (returned by strategies that embed pubkey, e.g. PRF) */
    pubkey?: string;
}
/** Passkey authentication options for decryption */
export interface AuthenticateOptions {
    credentialId: Uint8Array;
    rpId: string;
    transports?: AuthenticatorTransport[];
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
    /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
    hints?: string[];
}
/** Full encrypt-and-wrap result */
export interface KeytrBundle {
    credential: KeytrCredential;
    encryptedBlob: string;
    eventTemplate: KeytrEventTemplate;
}
/** Pluggable key derivation strategy */
export interface KeyStrategy {
    /** AAD version byte (e.g. 3 for KiH, 1 for PRF) */
    readonly version: number;
    /** Register a passkey, return credential + 32-byte key material */
    register(options: RegisterOptions): Promise<{
        credential: KeytrCredential;
        keyMaterial: Uint8Array;
    }>;
    /** Targeted auth with known credential, return 32-byte key material */
    authenticate(options: AuthenticateOptions): Promise<Uint8Array>;
    /** Discoverable auth, return key material + credential ID + optional pubkey */
    discover(options: DiscoverOptions): Promise<DiscoverResult>;
}
/** Browser WebAuthn capability report from getClientCapabilities() */
export interface WebAuthnCapabilities {
    /** Whether WebAuthn is available in this environment */
    webauthn: boolean;
    /** Whether a platform authenticator is available */
    platformAuthenticator: boolean;
    /** Whether conditional mediation (passkey autofill) is supported */
    conditionalMediation: boolean;
    /** Whether Related Origin Requests are supported (cross-domain passkey use; null = unknown) */
    relatedOrigins: boolean | null;
    /** Whether the WebAuthn Signal API is supported (credential lifecycle management) */
    signalApi: boolean;
}
//# sourceMappingURL=types.d.ts.map