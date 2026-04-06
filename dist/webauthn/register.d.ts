import type { RegisterOptions, RegisterResult } from '../types.js';
/**
 * Register a new passkey with a random encryption key embedded in user.id.
 *
 * The 32-byte encryption key is embedded in user.id as [0x03 || key].
 * Works with all authenticators including password manager extensions.
 * Single biometric prompt — no follow-up assertion needed.
 */
export declare function registerPasskey(options: RegisterOptions): Promise<RegisterResult>;
//# sourceMappingURL=register.d.ts.map