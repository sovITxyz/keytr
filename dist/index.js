export { KEYTR_VERSION, KEYTR_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME, KEYTR_GATEWAYS } from './types.js';
// Errors
export { KeytrError, PrfNotSupportedError, EncryptionError, DecryptionError, BlobParseError, WebAuthnError, RelayError, } from './errors.js';
// Crypto
export { encryptNsec } from './crypto/encrypt.js';
export { decryptNsec } from './crypto/decrypt.js';
export { deriveKey } from './crypto/kdf.js';
export { serializeBlob, deserializeBlob } from './crypto/blob.js';
// WebAuthn
export { checkPrfSupport } from './webauthn/support.js';
export { registerPasskey } from './webauthn/register.js';
export { authenticatePasskey, discoverPasskey } from './webauthn/authenticate.js';
// Nostr
export { generateNsec, nsecToPublicKey, encodeNsec, decodeNsec, encodeNpub, decodeNpub, nsecToNpub, nsecToHexPubkey, } from './nostr/keys.js';
export { buildKeytrEvent, parseKeytrEvent } from './nostr/event.js';
export { publishKeytrEvent, fetchKeytrEvents } from './nostr/relay.js';
import { DEFAULT_RP_ID } from './types.js';
import { WebAuthnError, RelayError, KeytrError } from './errors.js';
import { registerPasskey } from './webauthn/register.js';
import { authenticatePasskey } from './webauthn/authenticate.js';
import { discoverPasskey } from './webauthn/authenticate.js';
import { encryptNsec as _encryptNsec } from './crypto/encrypt.js';
import { decryptNsec as _decryptNsec } from './crypto/decrypt.js';
import { buildKeytrEvent as _buildEvent } from './nostr/event.js';
import { parseKeytrEvent as _parseEvent } from './nostr/event.js';
import { generateNsec as _generateNsec, nsecToNpub as _nsecToNpub, nsecToHexPubkey as _nsecToHexPubkey } from './nostr/keys.js';
import { fetchKeytrEvents as _fetchEvents } from './nostr/relay.js';
import { base64url } from '@scure/base';
/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * The pubkey is derived from the generated nsec and stored as WebAuthn user.id
 * to enable discoverable login.
 */
export async function setupKeytr(options) {
    const nsecBytes = _generateNsec();
    const npub = _nsecToNpub(nsecBytes);
    const pubkey = _nsecToHexPubkey(nsecBytes);
    const { credential, prfOutput } = await registerPasskey({ ...options, pubkey });
    try {
        const encryptedBlob = _encryptNsec({
            nsecBytes,
            prfOutput,
            credentialId: credential.credentialId,
        });
        const eventTemplate = _buildEvent({
            credential,
            encryptedBlob,
            clientName: options.clientName,
        });
        return { credential, encryptedBlob, eventTemplate, nsecBytes, npub };
    }
    finally {
        prfOutput.fill(0);
    }
}
/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 * The pubkey is derived from the provided nsec.
 */
export async function addBackupGateway(nsecBytes, options) {
    const pubkey = _nsecToHexPubkey(nsecBytes);
    const { credential, prfOutput } = await registerPasskey({ ...options, pubkey });
    try {
        const encryptedBlob = _encryptNsec({
            nsecBytes,
            prfOutput,
            credentialId: credential.credentialId,
        });
        const eventTemplate = _buildEvent({
            credential,
            encryptedBlob,
            clientName: options.clientName,
        });
        return { credential, encryptedBlob, eventTemplate };
    }
    finally {
        prfOutput.fill(0);
    }
}
/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:30079 events for this pubkey. The function tries each
 * event in order — the first passkey the authenticator recognises wins.
 * This works regardless of which gateway the passkey was registered with.
 */
export async function loginWithKeytr(events) {
    if (events.length === 0) {
        throw new WebAuthnError('No keytr events provided');
    }
    let lastError;
    for (const event of events) {
        const parsed = _parseEvent(event);
        let prfOutput;
        try {
            prfOutput = await authenticatePasskey({
                credentialId: parsed.credentialId,
                rpId: parsed.rpId,
                transports: parsed.transports,
            });
        }
        catch (err) {
            lastError = err;
            continue;
        }
        try {
            const nsecBytes = _decryptNsec({
                encryptedBlob: parsed.encryptedBlob,
                prfOutput,
                credentialId: parsed.credentialId,
            });
            const npub = _nsecToNpub(nsecBytes);
            return { nsecBytes, npub };
        }
        finally {
            prfOutput.fill(0);
        }
    }
    throw new WebAuthnError(`No matching passkey found across ${events.length} event(s): ${lastError?.message ?? 'unknown error'}`);
}
/**
 * Discoverable login: browser shows available passkeys, user picks one,
 * we recover the pubkey, fetch events, and decrypt the nsec.
 *
 * No prior knowledge of the user's pubkey or credential ID is needed.
 * Requires passkeys registered with pubkey as user.id (post-discoverable-login update).
 */
export async function discoverAndLogin(relays, options) {
    const { pubkey, prfOutput, credentialId } = await discoverPasskey({
        rpId: options?.rpId ?? DEFAULT_RP_ID,
        timeout: options?.timeout,
    });
    let events;
    try {
        events = await _fetchEvents(pubkey, relays);
    }
    catch (err) {
        prfOutput.fill(0);
        throw err;
    }
    if (!events.length) {
        prfOutput.fill(0);
        throw new RelayError('No keytr events found for this pubkey');
    }
    const credentialIdB64 = base64url.encode(credentialId);
    const matching = events.find(e => {
        const dTag = e.tags.find((t) => t[0] === 'd')?.[1];
        return dTag === credentialIdB64;
    });
    if (!matching) {
        prfOutput.fill(0);
        throw new KeytrError(`No event matches credential ${credentialIdB64} — ` +
            `passkey may have been registered before discoverable login was enabled`);
    }
    try {
        const parsed = _parseEvent(matching);
        const nsecBytes = _decryptNsec({
            encryptedBlob: parsed.encryptedBlob,
            prfOutput,
            credentialId,
        });
        const npub = _nsecToNpub(nsecBytes);
        return { nsecBytes, npub, pubkey };
    }
    finally {
        prfOutput.fill(0);
    }
}
//# sourceMappingURL=index.js.map