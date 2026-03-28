import type { AuthenticateOptions, DiscoverOptions, DiscoverResult } from '../types.js';
/**
 * Authenticate with an existing passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export declare function authenticatePasskey(options: AuthenticateOptions): Promise<Uint8Array>;
/**
 * Discoverable passkey authentication — no prior pubkey or credential ID needed.
 *
 * The browser shows all resident keys for this rpId and the user picks one.
 * The pubkey is recovered from WebAuthn userHandle (set during registration).
 *
 * @returns The recovered pubkey, PRF output, and credential ID
 */
export declare function discoverPasskey(options?: DiscoverOptions): Promise<DiscoverResult>;
//# sourceMappingURL=authenticate.d.ts.map