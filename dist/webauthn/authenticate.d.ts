import type { AuthenticateOptions, DiscoverOptions, DiscoverResult } from '../types.js';
/**
 * Authenticate with an existing passkey and extract the encryption key
 * from the userHandle for decrypting the nsec.
 *
 * @returns 32-byte encryption key from userHandle
 */
export declare function authenticatePasskey(options: AuthenticateOptions): Promise<Uint8Array>;
/**
 * Discoverable passkey authentication — no prior credential ID needed.
 *
 * Single-step flow: empty allowCredentials triggers the passkey picker,
 * the authenticator returns the userHandle with the embedded encryption key.
 *
 * @returns The encryption key and credential ID
 */
export declare function discoverPasskey(options?: DiscoverOptions): Promise<DiscoverResult>;
//# sourceMappingURL=authenticate.d.ts.map