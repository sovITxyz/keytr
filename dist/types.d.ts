/** AAD version byte for PRF mode (original) */
export declare const KEYTR_VERSION = 1;
/** AAD version byte for Key-in-Handle (KiH) mode */
export declare const KEYTR_KIH_VERSION = 3;
/** Size of the random encryption key embedded in KiH user.id */
export declare const KIH_KEY_SIZE = 32;
/** Total size of KiH user.id: mode byte (0x03) + 32-byte key */
export declare const KIH_USER_ID_SIZE = 33;
/** Mode prefix byte written as user.id[0] in KiH mode */
export declare const KIH_MODE_BYTE = 3;
/** PRF mode user.id size (32-byte pubkey) */
export declare const PRF_USER_ID_SIZE = 32;
/** Nostr event kind for passkey-encrypted private keys */
export declare const KEYTR_EVENT_KIND = 31777;
/** PRF salt used during WebAuthn ceremonies */
export declare const PRF_SALT: Uint8Array<ArrayBuffer>;
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
/** Result of passkey registration with PRF enabled */
export interface KeytrCredential {
    credentialId: Uint8Array;
    credentialIdBase64url: string;
    rpId: string;
    transports: AuthenticatorTransport[];
    prfSupported: boolean;
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
    prfOutput: Uint8Array;
    credentialId: Uint8Array;
    /** AAD version byte. Defaults to KEYTR_VERSION (1) for PRF, use KEYTR_KIH_VERSION (3) for KiH. */
    aadVersion?: number;
}
/** Options for decrypting an nsec */
export interface DecryptOptions {
    encryptedBlob: string;
    prfOutput: Uint8Array;
    credentialId: Uint8Array;
    /** AAD version byte. Defaults to KEYTR_VERSION (1) for PRF, use KEYTR_KIH_VERSION (3) for KiH. */
    aadVersion?: number;
}
/** PRF support detection result */
export interface PrfSupportInfo {
    supported: boolean;
    platformAuthenticator: boolean;
    reason?: string;
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
    /**
     * Hex-encoded 32-byte Nostr public key, stored as WebAuthn user.id.
     * This enables discoverable credential login — the browser returns
     * the pubkey via userHandle when the user picks a passkey.
     */
    pubkey: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
}
/** Options for discoverable passkey authentication (no prior pubkey needed) */
export interface DiscoverOptions {
    rpId?: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
}
/** Result of discoverable passkey authentication (PRF mode) */
export interface DiscoverResult {
    /** Hex-encoded Nostr public key recovered from WebAuthn userHandle */
    pubkey: string;
    /** 32-byte PRF output for key derivation */
    prfOutput: Uint8Array;
    /** Raw credential ID */
    credentialId: Uint8Array;
}
/** Encryption mode: PRF (authenticator-derived key) or KiH (key-in-handle) */
export type KeytrMode = 'prf' | 'kih';
/** Result of unified discoverable authentication (auto-detects PRF vs KiH) */
export interface UnifiedDiscoverResult {
    /** Detected mode based on userHandle length */
    mode: KeytrMode;
    /** 32-byte key material (PRF output or KiH handle key) */
    keyMaterial: Uint8Array;
    /** Raw credential ID */
    credentialId: Uint8Array;
    /** AAD version byte for this mode */
    aadVersion: number;
    /** Hex-encoded pubkey — only available in PRF mode (from userHandle) */
    pubkey?: string;
}
/** Options for KiH passkey registration (no PRF extension needed) */
export interface KihRegisterOptions {
    rpId?: string;
    rpName?: string;
    userName: string;
    userDisplayName: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
}
/** Result of KiH passkey registration */
export interface KihRegisterResult {
    credential: KeytrCredential;
    /** 32-byte random key extracted from user.id for encryption */
    handleKey: Uint8Array;
}
/** Passkey authentication options for decryption */
export interface AuthenticateOptions {
    credentialId: Uint8Array;
    rpId: string;
    transports?: AuthenticatorTransport[];
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
}
/** Full encrypt-and-wrap result */
export interface KeytrBundle {
    credential: KeytrCredential;
    encryptedBlob: string;
    eventTemplate: KeytrEventTemplate;
}
//# sourceMappingURL=types.d.ts.map