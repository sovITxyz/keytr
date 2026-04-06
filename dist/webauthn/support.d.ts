import type { WebAuthnCapabilities } from '../types.js';
/**
 * Throw if WebAuthn is not available (SSR / Node.js / non-browser environment).
 * Call at the top of any function that touches navigator.credentials.
 */
export declare function ensureBrowser(): void;
/**
 * Comprehensive capability check using getClientCapabilities() (Chrome 132+).
 * Falls back to feature detection for browsers without getClientCapabilities().
 */
export declare function checkCapabilities(): Promise<WebAuthnCapabilities>;
//# sourceMappingURL=support.d.ts.map