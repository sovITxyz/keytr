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
 * Uses a two-step flow to work around Safari iOS 18+ not returning PRF
 * extension output during discoverable authentication (empty allowCredentials):
 *
 *   Step 1 — Discovery (no PRF): empty allowCredentials, browser shows the
 *   passkey picker. Returns the credential ID (rawId) and pubkey (userHandle).
 *
 *   Step 2 — Targeted assertion WITH PRF: the discovered credentialId goes
 *   into allowCredentials so the browser can evaluate the PRF extension.
 *   This second assertion should be auto-approved since it targets the same
 *   credential that was just authenticated.
 *
 * @returns The recovered pubkey, PRF output, and credential ID
 */
export declare function discoverPasskey(options?: DiscoverOptions): Promise<DiscoverResult>;
//# sourceMappingURL=authenticate.d.ts.map