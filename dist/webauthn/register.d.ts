import type { KeytrCredential, RegisterOptions } from '../types.js';
/**
 * Register a new passkey with PRF extension enabled.
 *
 * This creates a discoverable credential (resident key) on the user's
 * authenticator with PRF support for key derivation.
 *
 * @returns The credential metadata and initial PRF output for first encryption
 */
export declare function registerPasskey(options: RegisterOptions): Promise<{
    credential: KeytrCredential;
    prfOutput: Uint8Array;
}>;
//# sourceMappingURL=register.d.ts.map