import type { AuthenticateOptions } from '../types.js'
import { WebAuthnError, PrfNotSupportedError } from '../errors.js'
import { prfAuthenticationExtension, extractPrfOutput } from './prf.js'

/**
 * Authenticate with an existing passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export async function authenticatePasskey(
  options: AuthenticateOptions
): Promise<Uint8Array> {
  const { credentialId, rpId, transports } = options

  const getOptions: CredentialRequestOptions = {
    publicKey: {
      rpId,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          type: 'public-key',
          id: credentialId.buffer as ArrayBuffer,
          transports: transports ?? [],
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
    if (!result) throw new WebAuthnError('Authentication returned null')
    assertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Passkey authentication failed: ${(err as Error).message}`)
  }

  const extensionResults = assertion.getClientExtensionResults()
  const prfOutput = extractPrfOutput(extensionResults)

  if (!prfOutput || prfOutput.length !== 32) {
    throw new PrfNotSupportedError(
      'PRF output not available during authentication. ' +
      'The authenticator may not support PRF.'
    )
  }

  return prfOutput
}
