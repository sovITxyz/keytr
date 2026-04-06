import { DEFAULT_RP_ID } from '../types.js';
import { WebAuthnError } from '../errors.js';
import { extractKey } from './kih.js';
import { ensureBrowser } from './support.js';
/**
 * Authenticate with an existing passkey and extract the encryption key
 * from the userHandle for decrypting the nsec.
 *
 * @returns 32-byte encryption key from userHandle
 */
export async function authenticatePasskey(options) {
    ensureBrowser();
    const { credentialId, rpId, transports } = options;
    const pubKeyOptions = {
        rpId,
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [
            {
                type: 'public-key',
                id: credentialId.buffer,
                transports: transports ?? [],
            },
        ],
        userVerification: 'required',
        timeout: options.timeout ?? 120000,
    };
    if (options.hints?.length) {
        ;
        pubKeyOptions.hints = options.hints;
    }
    const getOptions = { publicKey: pubKeyOptions };
    let assertion;
    try {
        const result = await navigator.credentials.get(getOptions);
        if (!result)
            throw new WebAuthnError('Authentication returned null');
        assertion = result;
    }
    catch (err) {
        if (err instanceof WebAuthnError)
            throw err;
        throw new WebAuthnError(`Passkey authentication failed: ${err.message}`);
    }
    const response = assertion.response;
    if (!response.userHandle || response.userHandle.byteLength === 0) {
        throw new WebAuthnError('Authenticator did not return a userHandle — cannot extract encryption key');
    }
    return extractKey(new Uint8Array(response.userHandle));
}
/**
 * Discoverable passkey authentication — no prior credential ID needed.
 *
 * Single-step flow: empty allowCredentials triggers the passkey picker,
 * the authenticator returns the userHandle with the embedded encryption key.
 *
 * @returns The encryption key and credential ID
 */
export async function discoverPasskey(options) {
    ensureBrowser();
    const rpId = options?.rpId ?? DEFAULT_RP_ID;
    const timeout = options?.timeout ?? 120000;
    const pubKeyOptions = {
        rpId,
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [],
        userVerification: 'required',
        timeout,
    };
    if (options?.hints?.length) {
        ;
        pubKeyOptions.hints = options.hints;
    }
    const discoveryOptions = { publicKey: pubKeyOptions };
    if (options?.mediation)
        discoveryOptions.mediation = options.mediation;
    let assertion;
    try {
        const result = await navigator.credentials.get(discoveryOptions);
        if (!result)
            throw new WebAuthnError('Discoverable authentication returned null');
        assertion = result;
    }
    catch (err) {
        if (err instanceof WebAuthnError)
            throw err;
        throw new WebAuthnError(`Discoverable passkey authentication failed: ${err.message}`);
    }
    const response = assertion.response;
    if (!response.userHandle || response.userHandle.byteLength === 0) {
        throw new WebAuthnError('Authenticator did not return a userHandle');
    }
    const userHandle = new Uint8Array(response.userHandle);
    const credentialId = new Uint8Array(assertion.rawId);
    const keyMaterial = extractKey(userHandle);
    return { keyMaterial, credentialId };
}
//# sourceMappingURL=authenticate.js.map