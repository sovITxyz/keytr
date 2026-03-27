import { randomBytes } from '@noble/hashes/utils'
import { base64url } from '@scure/base'
import type { KeytrCredential, RegisterOptions } from '../types.js'
import { DEFAULT_RP_ID, DEFAULT_RP_NAME } from '../types.js'
import { WebAuthnError, PrfNotSupportedError } from '../errors.js'
import { prfRegistrationExtension, prfAuthenticationExtension, isPrfEnabled, extractPrfOutput } from './prf.js'

/**
 * Register a new passkey with PRF extension enabled.
 *
 * This creates a discoverable credential (resident key) on the user's
 * authenticator with PRF support for key derivation.
 *
 * @returns The credential metadata and initial PRF output for first encryption
 */
export async function registerPasskey(
  options: RegisterOptions
): Promise<{ credential: KeytrCredential; prfOutput: Uint8Array }> {
  const rpId = options.rpId ?? DEFAULT_RP_ID
  const rpName = options.rpName ?? DEFAULT_RP_NAME
  const { userName, userDisplayName } = options
  const userId = randomBytes(32)

  const createOptions: CredentialCreationOptions = {
    publicKey: {
      rp: {
        id: rpId,
        name: rpName,
      },
      user: {
        id: userId.buffer.slice(0) as ArrayBuffer,
        name: userName,
        displayName: userDisplayName,
      },
      challenge: randomBytes(32).buffer.slice(0) as ArrayBuffer,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },    // ES256
        { type: 'public-key', alg: -257 },  // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      timeout: options.timeout ?? 120000,
      extensions: prfRegistrationExtension(),
    },
  }

  let cred: PublicKeyCredential
  try {
    const result = await navigator.credentials.create(createOptions)
    if (!result) throw new WebAuthnError('Credential creation returned null')
    cred = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Passkey registration failed: ${(err as Error).message}`)
  }

  const response = cred.response as AuthenticatorAttestationResponse
  const extensionResults = cred.getClientExtensionResults()
  const prfSupported = isPrfEnabled(extensionResults)

  if (!prfSupported) {
    throw new PrfNotSupportedError(
      'This authenticator does not support the PRF extension. ' +
      'Try using a platform authenticator (fingerprint/face) or a newer security key.'
    )
  }

  let prfOutput = extractPrfOutput(extensionResults)

  // Some authenticators (e.g. YubiKey) report prf.enabled=true during
  // registration but only return PRF output during authentication.
  // Fall back to an immediate assertion to obtain the PRF output.
  if (!prfOutput || prfOutput.length !== 32) {
    const credId = new Uint8Array(cred.rawId)
    const getOptions: CredentialRequestOptions = {
      publicKey: {
        rpId,
        challenge: randomBytes(32).buffer.slice(0) as ArrayBuffer,
        allowCredentials: [
          {
            type: 'public-key',
            id: credId.buffer.slice(0) as ArrayBuffer,
            transports: response.getTransports?.() as AuthenticatorTransport[] ?? [],
          },
        ],
        userVerification: 'required',
        timeout: options.timeout ?? 120000,
        extensions: prfAuthenticationExtension(),
      },
    }

    let assertion: PublicKeyCredential
    try {
      const result = await navigator.credentials.get(getOptions)
      if (!result) throw new WebAuthnError('Follow-up authentication returned null')
      assertion = result as PublicKeyCredential
    } catch (err) {
      if (err instanceof WebAuthnError) throw err
      throw new WebAuthnError(`Follow-up PRF authentication failed: ${(err as Error).message}`)
    }

    const assertionExtensions = assertion.getClientExtensionResults()
    prfOutput = extractPrfOutput(assertionExtensions)
    if (!prfOutput || prfOutput.length !== 32) {
      throw new PrfNotSupportedError('PRF output not available from this authenticator')
    }
  }

  const credentialId = new Uint8Array(cred.rawId)
  const transports = response.getTransports?.() as AuthenticatorTransport[] ?? []

  const credential: KeytrCredential = {
    credentialId,
    credentialIdBase64url: base64url.encode(credentialId),
    rpId,
    transports,
    prfSupported: true,
  }

  return { credential, prfOutput }
}
