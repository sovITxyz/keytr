export type { KeytrCredential, EncryptedNsecBlob, KeytrEventTemplate, EncryptOptions, DecryptOptions, PrfSupportInfo, RegisterOptions, AuthenticateOptions, DiscoverOptions, DiscoverResult, KeytrBundle, } from './types.js';
export { KEYTR_VERSION, KEYTR_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME, KEYTR_GATEWAYS } from './types.js';
export { KeytrError, PrfNotSupportedError, EncryptionError, DecryptionError, BlobParseError, WebAuthnError, RelayError, } from './errors.js';
export { encryptNsec } from './crypto/encrypt.js';
export { decryptNsec } from './crypto/decrypt.js';
export { deriveKey } from './crypto/kdf.js';
export { serializeBlob, deserializeBlob } from './crypto/blob.js';
export { checkPrfSupport } from './webauthn/support.js';
export { registerPasskey } from './webauthn/register.js';
export { authenticatePasskey, discoverPasskey } from './webauthn/authenticate.js';
export { generateNsec, nsecToPublicKey, encodeNsec, decodeNsec, encodeNpub, decodeNpub, nsecToNpub, nsecToHexPubkey, } from './nostr/keys.js';
export { buildKeytrEvent, parseKeytrEvent } from './nostr/event.js';
export { publishKeytrEvent, fetchKeytrEvents, type RelayOptions } from './nostr/relay.js';
import type { RegisterOptions, DiscoverOptions, KeytrBundle } from './types.js';
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
 * Pass all kind:30079 events for this pubkey. The function tries each
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
export declare function discoverAndLogin(relays: string[], options?: DiscoverOptions): Promise<{
    nsecBytes: Uint8Array;
    npub: string;
    pubkey: string;
}>;
//# sourceMappingURL=index.d.ts.map