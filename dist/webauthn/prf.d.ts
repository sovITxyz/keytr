/**
 * Build the PRF extension input for credential creation (registration).
 * During registration, we use `eval` to test if PRF is supported
 * and get the first PRF output.
 */
export declare function prfRegistrationExtension(): AuthenticationExtensionsClientInputs;
/**
 * Build the PRF extension input for credential assertion (authentication).
 * During authentication, we use `eval` to get the PRF output
 * for deriving the encryption/decryption key.
 */
export declare function prfAuthenticationExtension(): AuthenticationExtensionsClientInputs;
/**
 * Extract the 32-byte PRF output from a WebAuthn extension result.
 * Returns null if PRF was not supported/returned by the authenticator.
 */
export declare function extractPrfOutput(extensionResults: AuthenticationExtensionsClientOutputs): Uint8Array | null;
/**
 * Check if PRF was enabled during registration from extension outputs.
 */
export declare function isPrfEnabled(extensionResults: AuthenticationExtensionsClientOutputs): boolean;
//# sourceMappingURL=prf.d.ts.map