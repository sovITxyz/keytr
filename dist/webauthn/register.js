import { randomBytes, hexToBytes } from '@noble/hashes/utils.js';
import { base64url } from '@scure/base';
import { DEFAULT_RP_ID, DEFAULT_RP_NAME } from '../types.js';
import { WebAuthnError, PrfNotSupportedError } from '../errors.js';
import { prfRegistrationExtension, prfAuthenticationExtension, extractPrfOutput } from './prf.js';
/**
 * Register a new passkey with PRF extension enabled.
 *
 * This creates a discoverable credential (resident key) on the user's
 * authenticator with PRF support for key derivation.
 *
 * @returns The credential metadata and initial PRF output for first encryption
 */
export async function registerPasskey(options) {
    const rpId = options.rpId ?? DEFAULT_RP_ID;
    const rpName = options.rpName ?? DEFAULT_RP_NAME;
    const { userName, userDisplayName, pubkey } = options;
    const userId = hexToBytes(pubkey);
    const createOptions = {
        publicKey: {
            rp: {
                id: rpId,
                name: rpName,
            },
            user: {
                id: userId.buffer.slice(0),
                name: userName,
                displayName: userDisplayName,
            },
            challenge: randomBytes(32).buffer.slice(0),
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 }, // ES256
                { type: 'public-key', alg: -257 }, // RS256
            ],
            authenticatorSelection: {
                residentKey: 'required',
                requireResidentKey: true,
                userVerification: 'required',
            },
            timeout: options.timeout ?? 120000,
            extensions: prfRegistrationExtension(),
        },
    };
    let cred;
    try {
        const result = await navigator.credentials.create(createOptions);
        if (!result)
            throw new WebAuthnError('Credential creation returned null');
        cred = result;
    }
    catch (err) {
        if (err instanceof WebAuthnError)
            throw err;
        throw new WebAuthnError(`Passkey registration failed: ${err.message}`);
    }
    const response = cred.response;
    const extensionResults = cred.getClientExtensionResults();
    let prfOutput = extractPrfOutput(extensionResults);
    // Some authenticators (e.g. YubiKey) report prf.enabled=true during
    // registration but only return PRF output during authentication.
    // Fall back to an immediate assertion to obtain the PRF output.
    if (!prfOutput || prfOutput.length !== 32) {
        const credId = new Uint8Array(cred.rawId);
        const getOptions = {
            publicKey: {
                rpId,
                challenge: randomBytes(32).buffer.slice(0),
                allowCredentials: [
                    {
                        type: 'public-key',
                        id: credId.buffer.slice(0),
                        transports: response.getTransports?.() ?? [],
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
                throw new WebAuthnError('Follow-up authentication returned null');
            assertion = result;
        }
        catch (err) {
            if (err instanceof WebAuthnError)
                throw err;
            throw new WebAuthnError(`Follow-up PRF authentication failed: ${err.message}`);
        }
        const assertionExtensions = assertion.getClientExtensionResults();
        prfOutput = extractPrfOutput(assertionExtensions);
        if (!prfOutput || prfOutput.length !== 32) {
            throw new PrfNotSupportedError('PRF output not available from this authenticator');
        }
    }
    const credentialId = new Uint8Array(cred.rawId);
    const transports = response.getTransports?.() ?? [];
    const credential = {
        credentialId,
        credentialIdBase64url: base64url.encode(credentialId),
        rpId,
        transports,
        prfSupported: true,
    };
    return { credential, prfOutput };
}
//# sourceMappingURL=register.js.map