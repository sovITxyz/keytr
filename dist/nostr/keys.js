import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bech32 } from '@scure/base';
import { hexToBytes } from '@noble/hashes/utils';
const NSEC_PREFIX = 'nsec';
const NPUB_PREFIX = 'npub';
/** Generate a random 32-byte Nostr private key */
export function generateNsec() {
    return generateSecretKey();
}
/** Derive the hex public key from a 32-byte private key */
export function nsecToPublicKeyHex(nsecBytes) {
    return getPublicKey(nsecBytes);
}
/** Derive the public key bytes from a 32-byte private key */
export function nsecToPublicKey(nsecBytes) {
    return hexToBytes(getPublicKey(nsecBytes));
}
/** Encode a 32-byte private key as bech32 nsec */
export function encodeNsec(nsecBytes) {
    const words = bech32.toWords(nsecBytes);
    return bech32.encode(NSEC_PREFIX, words, 1500);
}
/** Decode a bech32 nsec string to 32-byte raw key */
export function decodeNsec(nsec) {
    const { prefix, words } = bech32.decode(nsec, 1500);
    if (prefix !== NSEC_PREFIX) {
        throw new Error(`Expected nsec prefix, got: ${prefix}`);
    }
    return new Uint8Array(bech32.fromWords(words));
}
/** Encode a 32-byte public key as bech32 npub */
export function encodeNpub(pubkeyBytes) {
    const words = bech32.toWords(pubkeyBytes);
    return bech32.encode(NPUB_PREFIX, words, 1500);
}
/** Decode a bech32 npub string to 32-byte raw public key */
export function decodeNpub(npub) {
    const { prefix, words } = bech32.decode(npub, 1500);
    if (prefix !== NPUB_PREFIX) {
        throw new Error(`Expected npub prefix, got: ${prefix}`);
    }
    return new Uint8Array(bech32.fromWords(words));
}
/** Get npub string from nsec bytes */
export function nsecToNpub(nsecBytes) {
    const pubkey = nsecToPublicKey(nsecBytes);
    return encodeNpub(pubkey);
}
/** Get hex-encoded public key from nsec bytes */
export function nsecToHexPubkey(nsecBytes) {
    return getPublicKey(nsecBytes);
}
//# sourceMappingURL=keys.js.map