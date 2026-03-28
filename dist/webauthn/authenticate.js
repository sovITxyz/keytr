import { bytesToHex } from '@noble/hashes/utils.js';
import { DEFAULT_RP_ID } from '../types.js';
import { WebAuthnError, PrfNotSupportedError } from '../errors.js';
import { prfAuthenticationExtension, extractPrfOutput } from './prf.js';
/**
 * Authenticate with an existing passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export async function authenticatePasskey(options) {
    const { credentialId, rpId, transports } = options;
    const getOptions = {
        publicKey: {
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
            extensions: prfAuthenticationExtension(),
        },
    };
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
    const extensionResults = assertion.getClientExtensionResults();
    const prfOutput = extractPrfOutput(extensionResults);
    if (!prfOutput || prfOutput.length !== 32) {
        throw new PrfNotSupportedError('PRF output not available during authentication. ' +
            'The authenticator may not support PRF.');
    }
    return prfOutput;
}
/**
 * Discoverable passkey authentication — no prior pubkey or credential ID needed.
 *
 * The browser shows all resident keys for this rpId and the user picks one.
 * The pubkey is recovered from WebAuthn userHandle (set during registration).
 *
 * @returns The recovered pubkey, PRF output, and credential ID
 */
export async function discoverPasskey(options) {
    const rpId = options?.rpId ?? DEFAULT_RP_ID;
    const getOptions = {
        publicKey: {
            rpId,
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [],
            userVerification: 'required',
            timeout: options?.timeout ?? 120000,
            extensions: prfAuthenticationExtension(),
        },
    };
    let assertion;
    try {
        const result = await navigator.credentials.get(getOptions);
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
        throw new WebAuthnError('Authenticator did not return a userHandle — cannot recover pubkey');
    }
    const pubkey = bytesToHex(new Uint8Array(response.userHandle));
    const extensionResults = assertion.getClientExtensionResults();
    const prfOutput = extractPrfOutput(extensionResults);
    if (!prfOutput || prfOutput.length !== 32) {
        throw new PrfNotSupportedError('PRF output not available during discoverable authentication. ' +
            'The authenticator may not support PRF.');
    }
    const credentialId = new Uint8Array(assertion.rawId);
    return { pubkey, prfOutput, credentialId };
}
//# sourceMappingURL=authenticate.js.map