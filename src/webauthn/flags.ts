/**
 * Parse backup eligibility (BE) and backup state (BS) flags from authenticatorData.
 *
 * authenticatorData layout:
 *   bytes 0-31:  rpIdHash (32 bytes)
 *   byte 32:     flags
 *     bit 0 (0x01): UP — User Present
 *     bit 2 (0x04): UV — User Verified
 *     bit 3 (0x08): BE — Backup Eligible (credential can sync across devices)
 *     bit 4 (0x10): BS — Backup State (credential is currently backed up)
 *     bit 6 (0x40): AT — Attested credential data included
 *     bit 7 (0x80): ED — Extension data included
 */
export function parseBackupFlags(
  response: AuthenticatorAttestationResponse
): { backupEligible: boolean; backupState: boolean } | undefined {
  try {
    const authData = new Uint8Array(response.getAuthenticatorData())
    if (authData.length < 33) return undefined
    const flags = authData[32]
    return {
      backupEligible: !!(flags & 0x08),
      backupState: !!(flags & 0x10),
    }
  } catch {
    // getAuthenticatorData() may not be available in older browsers
    return undefined
  }
}
