/** Blob version for the encrypted nsec format */
export const KEYTR_VERSION = 1;
/** Nostr event kind for passkey-encrypted private keys */
export const KEYTR_EVENT_KIND = 30079;
/** PRF salt used during WebAuthn ceremonies */
export const PRF_SALT = new TextEncoder().encode('keytr-v1');
/** HKDF info string for key derivation */
export const HKDF_INFO = 'keytr nsec encryption v1';
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
export const DEFAULT_RP_ID = 'keytr.org';
export const DEFAULT_RP_NAME = 'keytr';
/**
 * Well-known passkey gateways.
 * The primary gateway is used during initial setup (1 biometric prompt).
 * Additional gateways can be registered later via addBackupGateway().
 */
export const KEYTR_GATEWAYS = ['keytr.org', 'nostkey.org'];
//# sourceMappingURL=types.js.map