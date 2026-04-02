import { bytesToHex } from '@noble/hashes/utils.js'
import type { AuthenticateOptions, DiscoverOptions, DiscoverResult, UnifiedDiscoverResult } from '../types.js'
import { DEFAULT_RP_ID, KEYTR_VERSION, KEYTR_KIH_VERSION } from '../types.js'
import { WebAuthnError, PrfNotSupportedError } from '../errors.js'
import { prfAuthenticationExtension, extractPrfOutput } from './prf.js'
import { detectMode, extractKihKey } from './kih.js'
import { ensureBrowser } from './support.js'

/**
 * Authenticate with an existing passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export async function authenticatePasskey(
  options: AuthenticateOptions
): Promise<Uint8Array> {
  ensureBrowser()

  const { credentialId, rpId, transports } = options

  const pubKeyOptions: PublicKeyCredentialRequestOptions = {
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
  }

  if (options.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const getOptions: CredentialRequestOptions = { publicKey: pubKeyOptions }

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
export async function discoverPasskey(
  options?: DiscoverOptions
): Promise<DiscoverResult> {
  ensureBrowser()

  const rpId = options?.rpId ?? DEFAULT_RP_ID
  const timeout = options?.timeout ?? 120000

  // Step 1: Discovery — no PRF, empty allowCredentials
  const pubKeyOptions: PublicKeyCredentialRequestOptions = {
    rpId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [],
    userVerification: 'required',
    timeout,
  }

  if (options?.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const discoveryOptions: CredentialRequestOptions = {
    mediation: options?.mediation,
    publicKey: pubKeyOptions,
  }

  let assertion: PublicKeyCredential
  try {
    const result = await navigator.credentials.get(discoveryOptions)
    if (!result) throw new WebAuthnError('Discoverable authentication returned null')
    assertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Discoverable passkey authentication failed: ${(err as Error).message}`)
  }

  const response = assertion.response as AuthenticatorAssertionResponse
  if (!response.userHandle || response.userHandle.byteLength === 0) {
    throw new WebAuthnError('Authenticator did not return a userHandle — cannot recover pubkey')
  }

  const pubkey = bytesToHex(new Uint8Array(response.userHandle))
  const credentialId = new Uint8Array(assertion.rawId)

  // Step 2: Targeted assertion WITH PRF
  const prfOptions: CredentialRequestOptions = {
    publicKey: {
      rpId,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          type: 'public-key',
          id: credentialId.buffer as ArrayBuffer,
        },
      ],
      userVerification: 'required',
      timeout,
      extensions: prfAuthenticationExtension(),
    },
  }

  let prfAssertion: PublicKeyCredential
  try {
    const result = await navigator.credentials.get(prfOptions)
    if (!result) throw new WebAuthnError('PRF follow-up authentication returned null')
    prfAssertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`PRF follow-up authentication failed: ${(err as Error).message}`)
  }

  const extensionResults = prfAssertion.getClientExtensionResults()
  const prfOutput = extractPrfOutput(extensionResults)

  if (!prfOutput || prfOutput.length !== 32) {
    throw new PrfNotSupportedError(
      'PRF output not available during discoverable authentication. ' +
      'The authenticator may not support PRF.'
    )
  }

  return { pubkey, prfOutput, credentialId }
}

/**
 * Unified discoverable authentication — auto-detects PRF vs KiH mode.
 *
 * Step 1: Discovery assertion (no PRF, empty allowCredentials).
 *   - If userHandle is 33 bytes with 0x03 prefix → KiH mode. Done in 1 prompt.
 *   - If userHandle is 32 bytes → PRF mode. Needs step 2 for PRF output.
 *
 * Step 2 (PRF only): Targeted assertion with PRF extension to get key material.
 *
 * @returns Mode, key material, credential ID, and AAD version
 */
export async function unifiedDiscover(
  options?: DiscoverOptions
): Promise<UnifiedDiscoverResult> {
  ensureBrowser()

  const rpId = options?.rpId ?? DEFAULT_RP_ID
  const timeout = options?.timeout ?? 120000

  // Step 1: Discovery — no PRF, empty allowCredentials
  const pubKeyOptions: PublicKeyCredentialRequestOptions = {
    rpId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [],
    userVerification: 'required',
    timeout,
  }

  if (options?.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const discoveryOptions: CredentialRequestOptions = {
    mediation: options?.mediation,
    publicKey: pubKeyOptions,
  }

  let assertion: PublicKeyCredential
  try {
    const result = await navigator.credentials.get(discoveryOptions)
    if (!result) throw new WebAuthnError('Discoverable authentication returned null')
    assertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Discoverable passkey authentication failed: ${(err as Error).message}`)
  }

  const response = assertion.response as AuthenticatorAssertionResponse
  if (!response.userHandle || response.userHandle.byteLength === 0) {
    throw new WebAuthnError('Authenticator did not return a userHandle')
  }

  const userHandle = new Uint8Array(response.userHandle)
  const credentialId = new Uint8Array(assertion.rawId)
  const mode = detectMode(userHandle)

  if (mode === 'kih') {
    // KiH: key is in the userHandle, no step 2 needed
    const keyMaterial = extractKihKey(userHandle)
    return {
      mode: 'kih',
      keyMaterial,
      credentialId,
      aadVersion: KEYTR_KIH_VERSION,
    }
  }

  // PRF mode: userHandle is the pubkey, need step 2 for PRF output
  const pubkey = bytesToHex(userHandle)

  const prfOptions: CredentialRequestOptions = {
    publicKey: {
      rpId,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          type: 'public-key',
          id: credentialId.buffer as ArrayBuffer,
        },
      ],
      userVerification: 'required',
      timeout,
      extensions: prfAuthenticationExtension(),
    },
  }

  let prfAssertion: PublicKeyCredential
  try {
    const result = await navigator.credentials.get(prfOptions)
    if (!result) throw new WebAuthnError('PRF follow-up authentication returned null')
    prfAssertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`PRF follow-up authentication failed: ${(err as Error).message}`)
  }

  const extensionResults = prfAssertion.getClientExtensionResults()
  const prfOutput = extractPrfOutput(extensionResults)

  if (!prfOutput || prfOutput.length !== 32) {
    throw new PrfNotSupportedError(
      'PRF output not available during discoverable authentication. ' +
      'The authenticator may not support PRF.'
    )
  }

  return {
    mode: 'prf',
    keyMaterial: prfOutput,
    credentialId,
    aadVersion: KEYTR_VERSION,
    pubkey,
  }
}
