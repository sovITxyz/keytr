export type { KeytrCredential, EncryptedNsecBlob, KeytrEventTemplate, EncryptOptions, DecryptOptions, PrfSupportInfo, RegisterOptions, AuthenticateOptions, DiscoverOptions, DiscoverResult, KeytrBundle, KeytrMode, UnifiedDiscoverResult, KihRegisterOptions, KihRegisterResult, WebAuthnCapabilities, } from './types.js';
export { KEYTR_VERSION, KEYTR_KIH_VERSION, KEYTR_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME, KEYTR_GATEWAYS, KIH_KEY_SIZE, KIH_USER_ID_SIZE, KIH_MODE_BYTE, PRF_USER_ID_SIZE, } from './types.js';
export { KeytrError, PrfNotSupportedError, EncryptionError, DecryptionError, BlobParseError, WebAuthnError, RelayError, } from './errors.js';
export { encryptNsec, buildAad } from './crypto/encrypt.js';
export { decryptNsec } from './crypto/decrypt.js';
export { deriveKey } from './crypto/kdf.js';
export { serializeBlob, deserializeBlob } from './crypto/blob.js';
export { checkPrfSupport, checkCapabilities, ensureBrowser } from './webauthn/support.js';
export { registerPasskey } from './webauthn/register.js';
export { registerKihPasskey } from './webauthn/register-kih.js';
export { authenticatePasskey, discoverPasskey, unifiedDiscover } from './webauthn/authenticate.js';
export { generateKihUserId, detectMode, extractKihKey } from './webauthn/kih.js';
export { parseBackupFlags } from './webauthn/flags.js';
export { signalUnknownCredential, signalAllAcceptedCredentialIds, signalCurrentUserDetails, } from './webauthn/signal.js';
export { generateNsec, nsecToPublicKey, encodeNsec, decodeNsec, encodeNpub, decodeNpub, nsecToNpub, nsecToHexPubkey, } from './nostr/keys.js';
export { buildKeytrEvent, parseKeytrEvent, type ParsedKeytrEvent } from './nostr/event.js';
export { publishKeytrEvent, fetchKeytrEvents, fetchKeytrEventByDTag, type RelayOptions } from './nostr/relay.js';
import type { RegisterOptions, DiscoverOptions, KeytrBundle, KeytrMode } from './types.js';
import type { RelayOptions } from './nostr/relay.js';
/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * The pubkey is derived from the generated nsec and stored as WebAuthn user.id
 * to enable discoverable login.
 */
export declare function setupKeytr(options: Omit<RegisterOptions, 'pubkey'> & {
    clientName?: string;
}): Promise<KeytrBundle & {
    nsecBytes: Uint8Array;
    npub: string;
}>;
/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 * The pubkey is derived from the provided nsec.
 */
export declare function addBackupGateway(nsecBytes: Uint8Array, options: Omit<RegisterOptions, 'pubkey'> & {
    clientName?: string;
}): Promise<KeytrBundle>;
/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:31777 events for this pubkey. The function tries each
 * event in order — the first passkey the authenticator recognises wins.
 * This works regardless of which gateway the passkey was registered with.
 */
export declare function loginWithKeytr(events: {
    kind: number;
    content: string;
    tags: string[][];
}[]): Promise<{
    nsecBytes: Uint8Array;
    npub: string;
}>;
/**
 * Discoverable login: browser shows available passkeys, user picks one,
 * we recover the pubkey, fetch events, and decrypt the nsec.
 *
 * No prior knowledge of the user's pubkey or credential ID is needed.
 * Requires passkeys registered with pubkey as user.id (post-discoverable-login update).
 */
export declare function discoverAndLogin(relays: string[], options?: DiscoverOptions & {
    relayOptions?: RelayOptions;
}): Promise<{
    nsecBytes: Uint8Array;
    npub: string;
    pubkey: string;
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
}
/** Result of the unified setup flow */
export interface SetupResult extends KeytrBundle {
    nsecBytes: Uint8Array;
    npub: string;
    mode: KeytrMode;
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
export declare function setup(options: SetupOptions): Promise<SetupResult>;
/** Result of the unified discover flow */
export interface DiscoverLoginResult {
    nsecBytes: Uint8Array;
    npub: string;
    pubkey: string;
    mode: KeytrMode;
}
/**
 * Unified discoverable login: auto-detects PRF vs KiH from userHandle length.
 *
 * 1. Discovery assertion (1 biometric prompt for both modes)
 * 2. If PRF: step-2 targeted assertion for PRF output, then query by pubkey
 * 3. If KiH: extract key from userHandle, query relay by #d tag
 * 4. Decrypt nsec, derive pubkey, verify against event.pubkey
 */
export declare function discover(relays: string[], options?: DiscoverOptions & {
    relayOptions?: RelayOptions;
}): Promise<DiscoverLoginResult>;
//# sourceMappingURL=index.d.ts.map