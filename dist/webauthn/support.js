/** Check if the browser supports WebAuthn and the PRF extension */
export async function checkPrfSupport() {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
        return { supported: false, platformAuthenticator: false, reason: 'WebAuthn not available' };
    }
    let platformAuthenticator = false;
    try {
        platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
    catch {
        // Not critical, continue
    }
    // Check if the browser understands the PRF extension at all.
    // We can't fully verify PRF until a credential is created,
    // but we can check for the API surface.
    const hasCredentialsApi = typeof navigator.credentials?.create === 'function';
    if (!hasCredentialsApi) {
        return { supported: false, platformAuthenticator, reason: 'Credentials API not available' };
    }
    // PRF extension is available in Chrome 116+, Safari 18+, Edge 116+, Firefox 122+
    // We can't detect PRF capability without creating a credential,
    // so we report optimistically and check at registration time.
    return { supported: true, platformAuthenticator };
}
//# sourceMappingURL=support.js.map