import type { AuthenticateOptions } from '../types.js';
/**
 * Authenticate with an existing passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export declare function authenticatePasskey(options: AuthenticateOptions): Promise<Uint8Array>;
//# sourceMappingURL=authenticate.d.ts.map