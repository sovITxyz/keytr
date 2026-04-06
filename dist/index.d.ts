export type { KeytrCredential, EncryptedNsecBlob, KeytrEventTemplate, EncryptOptions, DecryptOptions, RegisterOptions, RegisterResult, AuthenticateOptions, DiscoverOptions, DiscoverResult, KeytrBundle, KeyStrategy, WebAuthnCapabilities, } from './types.js';
export { KEYTR_VERSION, BLOB_VERSION, KEYTR_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME, KEYTR_GATEWAYS, KEY_SIZE, USER_ID_SIZE, MODE_BYTE, } from './types.js';
export { KeytrError, EncryptionError, DecryptionError, BlobParseError, WebAuthnError, RelayError, } from './errors.js';
export { encryptNsec, buildAad } from './crypto/encrypt.js';
export { decryptNsec } from './crypto/decrypt.js';
export { deriveKey } from './crypto/kdf.js';
export { serializeBlob, deserializeBlob } from './crypto/blob.js';
export { checkCapabilities, ensureBrowser } from './webauthn/support.js';
export { registerPasskey } from './webauthn/register.js';
export { authenticatePasskey, discoverPasskey } from './webauthn/authenticate.js';
export { generateUserId, extractKey } from './webauthn/kih.js';
export { parseBackupFlags } from './webauthn/flags.js';
export { signalUnknownCredential, signalAllAcceptedCredentialIds, signalCurrentUserDetails, } from './webauthn/signal.js';
export { generateNsec, nsecToPublicKey, encodeNsec, decodeNsec, encodeNpub, decodeNpub, nsecToNpub, nsecToHexPubkey, } from './nostr/keys.js';
export { buildKeytrEvent, parseKeytrEvent, type ParsedKeytrEvent } from './nostr/event.js';
export { publishKeytrEvent, fetchKeytrEvents, fetchKeytrEventByDTag, type RelayOptions } from './nostr/relay.js';
import type { RegisterOptions, DiscoverOptions, KeytrBundle, KeyStrategy } from './types.js';
import type { RelayOptions } from './nostr/relay.js';
/** Built-in KiH (Key-in-Handle) strategy — the default */
export declare const kihStrategy: KeyStrategy;
/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * Single biometric prompt — the encryption key is embedded in the passkey's user.id.
 */
export declare function setupKeytr(options: RegisterOptions & {
    clientName?: string;
    strategy?: KeyStrategy;
}): Promise<KeytrBundle & {
    nsecBytes: Uint8Array;
    npub: string;
}>;
/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 */
export declare function addBackupGateway(nsecBytes: Uint8Array, options: RegisterOptions & {
    clientName?: string;
    strategy?: KeyStrategy;
}): Promise<KeytrBundle>;
/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:31777 events for this user. The function tries each
 * event in order — the first passkey the authenticator recognises wins.
 * The encryption key is extracted from the passkey's userHandle.
 */
export declare function loginWithKeytr(events: {
    kind: number;
    content: string;
    tags: string[][];
}[], strategy?: KeyStrategy): Promise<{
    nsecBytes: Uint8Array;
    npub: string;
}>;
/** Options for the unified setup flow */
export interface SetupOptions {
    rpId?: string;
    rpName?: string;
    userName: string;
    userDisplayName: string;
    clientName?: string;
    timeout?: number;
    /** WebAuthn Level 3 hints to guide authenticator selection */
    hints?: string[];
    /** Key derivation strategy. Defaults to kihStrategy (Key-in-Handle). */
    strategy?: KeyStrategy;
}
/** Result of the unified setup flow */
export interface SetupResult extends KeytrBundle {
    nsecBytes: Uint8Array;
    npub: string;
}
/**
 * Setup: generate nsec, register passkey, encrypt, build event.
 *
 * The encryption key is embedded in the passkey's user.id (33 bytes, 0x03 prefix).
 * Works with all authenticators including password manager extensions.
 * Single biometric prompt.
 */
export declare function setup(options: SetupOptions): Promise<SetupResult>;
/** Result of the discover flow */
export interface DiscoverLoginResult {
    nsecBytes: Uint8Array;
    npub: string;
    pubkey: string;
}
/**
 * Discoverable login: browser shows available passkeys, user picks one,
 * we extract the encryption key from userHandle, fetch the event, and decrypt.
 *
 * Single biometric prompt. No prior knowledge of the user needed.
 */
export declare function discover(relays: string[], options?: DiscoverOptions & {
    relayOptions?: RelayOptions;
    strategy?: KeyStrategy;
}): Promise<DiscoverLoginResult>;
//# sourceMappingURL=index.d.ts.map