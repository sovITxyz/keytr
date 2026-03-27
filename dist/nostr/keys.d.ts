/** Generate a random 32-byte Nostr private key */
export declare function generateNsec(): Uint8Array;
/** Derive the hex public key from a 32-byte private key */
export declare function nsecToPublicKeyHex(nsecBytes: Uint8Array): string;
/** Derive the public key bytes from a 32-byte private key */
export declare function nsecToPublicKey(nsecBytes: Uint8Array): Uint8Array;
/** Encode a 32-byte private key as bech32 nsec */
export declare function encodeNsec(nsecBytes: Uint8Array): string;
/** Decode a bech32 nsec string to 32-byte raw key */
export declare function decodeNsec(nsec: string): Uint8Array;
/** Encode a 32-byte public key as bech32 npub */
export declare function encodeNpub(pubkeyBytes: Uint8Array): string;
/** Decode a bech32 npub string to 32-byte raw public key */
export declare function decodeNpub(npub: string): Uint8Array;
/** Get npub string from nsec bytes */
export declare function nsecToNpub(nsecBytes: Uint8Array): string;
/** Get hex-encoded public key from nsec bytes */
export declare function nsecToHexPubkey(nsecBytes: Uint8Array): string;
//# sourceMappingURL=keys.d.ts.map