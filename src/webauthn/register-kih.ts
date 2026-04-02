import { randomBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import type { KeytrCredential, KihRegisterOptions, KihRegisterResult } from '../types.js'
import { DEFAULT_RP_ID, DEFAULT_RP_NAME } from '../types.js'
import { WebAuthnError } from '../errors.js'
import { generateKihUserId, extractKihKey } from './kih.js'
import { ensureBrowser } from './support.js'
import { parseBackupFlags } from './flags.js'

/**
 * Register a new passkey in KiH mode (no PRF extension required).
 *
 * The 32-byte encryption key is embedded in user.id as [0x03 || key].
 * This works with all authenticators including password manager extensions
 * (1Password, Bitwarden, Dashlane) that don't support PRF.
 *
 * Single biometric prompt — no follow-up assertion needed.
 */
export async function registerKihPasskey(
  options: KihRegisterOptions
): Promise<KihRegisterResult> {
  ensureBrowser()

  const rpId = options.rpId ?? DEFAULT_RP_ID
  const rpName = options.rpName ?? DEFAULT_RP_NAME
  const { userName, userDisplayName } = options

  const userId = generateKihUserId()

  const pubKeyOptions: PublicKeyCredentialCreationOptions = {
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
    // No PRF extension — KiH doesn't need it
  }

  // WebAuthn Level 3 hints for authenticator routing
  if (options.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const createOptions: CredentialCreationOptions = { publicKey: pubKeyOptions }

  let cred: PublicKeyCredential
  try {
    const result = await navigator.credentials.create(createOptions)
    if (!result) throw new WebAuthnError('Credential creation returned null')
    cred = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`KiH passkey registration failed: ${(err as Error).message}`)
  }

  const response = cred.response as AuthenticatorAttestationResponse
  const credentialId = new Uint8Array(cred.rawId)
  const transports = response.getTransports?.() as AuthenticatorTransport[] ?? []
  const backup = parseBackupFlags(response)

  const credential: KeytrCredential = {
    credentialId,
    credentialIdBase64url: base64url.encode(credentialId),
    rpId,
    transports,
    prfSupported: false,
    ...backup && { backupEligible: backup.backupEligible, backupState: backup.backupState },
  }

  const handleKey = extractKihKey(userId)

  return { credential, handleKey }
}
