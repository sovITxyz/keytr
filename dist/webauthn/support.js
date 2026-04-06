import { WebAuthnError } from '../errors.js';
/**
 * Throw if WebAuthn is not available (SSR / Node.js / non-browser environment).
 * Call at the top of any function that touches navigator.credentials.
 */
export function ensureBrowser() {
    if (typeof navigator === 'undefined' || typeof navigator.credentials?.create !== 'function') {
        throw new WebAuthnError('WebAuthn is not available in this environment (SSR/Node.js)');
    }
}
/**
 * Comprehensive capability check using getClientCapabilities() (Chrome 132+).
 * Falls back to feature detection for browsers without getClientCapabilities().
 */
export async function checkCapabilities() {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
        return {
            webauthn: false,
            platformAuthenticator: false,
            conditionalMediation: false,
            relatedOrigins: false,
            signalApi: false,
        };
    }
    let platformAuthenticator = false;
    try {
        platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
    catch {
        // ignore
    }
    // Try getClientCapabilities() for accurate browser-reported capabilities
    const caps = await _getRawCapabilities();
    if (caps) {
        return {
            webauthn: true,
            platformAuthenticator,
            conditionalMediation: caps['conditionalGet'] === true,
            relatedOrigins: caps['relatedOrigins'] === true,
            signalApi: caps['signalAllAcceptedCredentialIds'] === true
                || caps['signalUnknownCredential'] === true,
        };
    }
    // Fallback: feature-detect what we can
    let conditionalMediation = false;
    try {
        if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
            conditionalMediation = await PublicKeyCredential.isConditionalMediationAvailable();
        }
    }
    catch {
        // ignore
    }
    return {
        webauthn: true,
        platformAuthenticator,
        conditionalMediation,
        relatedOrigins: null, // Can't detect without getClientCapabilities
        signalApi: typeof PublicKeyCredential.signalUnknownCredential === 'function',
    };
}
/** Internal: call getClientCapabilities() if available */
async function _getRawCapabilities() {
    try {
        if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
            return await PublicKeyCredential.getClientCapabilities();
        }
    }
    catch {
        // ignore
    }
    return null;
}
//# sourceMappingURL=support.js.map