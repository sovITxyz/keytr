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
export async function discoverPasskey(options) {
    const rpId = options?.rpId ?? DEFAULT_RP_ID;
    const timeout = options?.timeout ?? 120000;
    // Step 1: Discovery — no PRF, empty allowCredentials
    const discoveryOptions = {
        publicKey: {
            rpId,
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [],
            userVerification: 'required',
            timeout,
        },
    };
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
        throw new WebAuthnError('Authenticator did not return a userHandle — cannot recover pubkey');
    }
    const pubkey = bytesToHex(new Uint8Array(response.userHandle));
    const credentialId = new Uint8Array(assertion.rawId);
    // Step 2: Targeted assertion WITH PRF
    const prfOptions = {
        publicKey: {
            rpId,
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [
                {
                    type: 'public-key',
                    id: credentialId.buffer,
                },
            ],
            userVerification: 'required',
            timeout,
            extensions: prfAuthenticationExtension(),
        },
    };
    let prfAssertion;
    try {
        const result = await navigator.credentials.get(prfOptions);
        if (!result)
            throw new WebAuthnError('PRF follow-up authentication returned null');
        prfAssertion = result;
    }
    catch (err) {
        if (err instanceof WebAuthnError)
            throw err;
        throw new WebAuthnError(`PRF follow-up authentication failed: ${err.message}`);
    }
    const extensionResults = prfAssertion.getClientExtensionResults();
    const prfOutput = extractPrfOutput(extensionResults);
    if (!prfOutput || prfOutput.length !== 32) {
        throw new PrfNotSupportedError('PRF output not available during discoverable authentication. ' +
            'The authenticator may not support PRF.');
    }
    return { pubkey, prfOutput, credentialId };
}
//# sourceMappingURL=authenticate.js.map