/** Blob binary format version (layout: version(1) | iv(12) | salt(32) | ct(48)) */
export const BLOB_VERSION = 1;
/** Protocol / AAD version for events and encryption */
export const KEYTR_VERSION = 3;
/** Size of the random encryption key embedded in user.id */
export const KEY_SIZE = 32;
/** Total size of user.id: mode byte (0x03) + 32-byte key */
export const USER_ID_SIZE = 33;
/** Mode prefix byte written as user.id[0] */
export const MODE_BYTE = 0x03;
/** Nostr event kind for passkey-encrypted private keys */
export const KEYTR_EVENT_KIND = 31777;
/** HKDF info string for key derivation */
export const HKDF_INFO = 'keytr nsec encryption v1';
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
export const DEFAULT_RP_ID = 'keytr.org';
export const DEFAULT_RP_NAME = 'keytr';
/**
 * Well-known passkey gateways.
 * The primary gateway is used during initial setup (1 biometric prompt).
 * Additional gateways can be registered later via addBackupGateway().
 */
export const KEYTR_GATEWAYS = ['keytr.org', 'nostkey.org'];
//# sourceMappingURL=types.js.map