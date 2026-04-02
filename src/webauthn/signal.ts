import { base64url } from '@scure/base'

/**
 * WebAuthn Signal API wrappers (Chrome 132+).
 *
 * These methods let the relying party tell authenticators about credential
 * lifecycle changes so they can clean up stale passkeys on the user's devices.
 * All methods are no-ops when the Signal API is not available.
 */

/**
 * Signal that a credential is unknown to this relying party.
 * The authenticator may delete or deprioritize it.
 */
export async function signalUnknownCredential(
  rpId: string,
  credentialId: Uint8Array
): Promise<boolean> {
  try {
    const pkc = window.PublicKeyCredential as any
    if (typeof pkc?.signalUnknownCredential !== 'function') return false
    await pkc.signalUnknownCredential({
      rpId,
      credentialId: base64url.encode(credentialId),
    })
    return true
  } catch {
    return false
  }
}

/**
 * Signal the full set of credential IDs that the RP accepts for a user.
 * Authenticators may remove credentials not in this list.
 */
export async function signalAllAcceptedCredentialIds(
  rpId: string,
  userId: Uint8Array,
  credentialIds: Uint8Array[]
): Promise<boolean> {
  try {
    const pkc = window.PublicKeyCredential as any
    if (typeof pkc?.signalAllAcceptedCredentialIds !== 'function') return false
    await pkc.signalAllAcceptedCredentialIds({
      rpId,
      userId: base64url.encode(userId),
      allAcceptedCredentialIds: credentialIds.map(id => base64url.encode(id)),
    })
    return true
  } catch {
    return false
  }
}

/**
 * Signal updated user details (name, display name) for a credential.
 * Authenticators may update the passkey metadata shown to the user.
 */
export async function signalCurrentUserDetails(
  rpId: string,
  userId: Uint8Array,
  name: string,
  displayName: string
): Promise<boolean> {
  try {
    const pkc = window.PublicKeyCredential as any
    if (typeof pkc?.signalCurrentUserDetails !== 'function') return false
    await pkc.signalCurrentUserDetails({
      rpId,
      userId: base64url.encode(userId),
      name,
      displayName,
    })
    return true
  } catch {
    return false
  }
}
