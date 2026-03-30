import { base64url } from '@scure/base'
import { KEYTR_EVENT_KIND, KEYTR_VERSION, KEYTR_KIH_VERSION, type KeytrEventTemplate, type KeytrCredential, type KeytrMode } from '../types.js'
import { KeytrError } from '../errors.js'

interface BuildEventOptions {
  credential: KeytrCredential
  encryptedBlob: string
  clientName?: string
  /** Version tag value. Defaults to '1' (PRF). Use '3' for KiH mode. */
  version?: string
}

/** Build an unsigned kind:31777 event template for a passkey-encrypted nsec */
export function buildKeytrEvent(options: BuildEventOptions): KeytrEventTemplate {
  const { credential, encryptedBlob, clientName } = options

  const tags: string[][] = [
    ['d', credential.credentialIdBase64url],
    ['rp', credential.rpId],
    ['algo', 'aes-256-gcm'],
    ['kdf', 'hkdf-sha256'],
    ['v', options.version ?? '1'],
  ]

  if (credential.transports.length > 0) {
    tags.push(['transports', ...credential.transports])
  }

  if (clientName) {
    tags.push(['client', clientName])
  }

  return {
    kind: KEYTR_EVENT_KIND,
    content: encryptedBlob,
    tags,
    created_at: Math.floor(Date.now() / 1000),
  }
}

export interface ParsedKeytrEvent {
  credentialIdBase64url: string
  credentialId: Uint8Array
  rpId: string
  encryptedBlob: string
  version: number
  algorithm: string
  kdf: string
  transports: string[]
  clientName?: string
  /** Detected encryption mode based on the v tag */
  mode: KeytrMode
}

/** Parse a kind:31777 event to extract credential info and encrypted blob */
export function parseKeytrEvent(event: {
  kind: number
  content: string
  tags: string[][]
}): ParsedKeytrEvent {
  if (event.kind !== KEYTR_EVENT_KIND) {
    throw new KeytrError(`Expected kind ${KEYTR_EVENT_KIND}, got ${event.kind}`)
  }

  const getTag = (name: string): string | undefined =>
    event.tags.find(t => t[0] === name)?.[1]

  const credentialIdBase64url = getTag('d')
  if (!credentialIdBase64url) {
    throw new KeytrError('Missing "d" tag (credential ID)')
  }

  const rpId = getTag('rp')
  if (!rpId) {
    throw new KeytrError('Missing "rp" tag')
  }

  const version = parseInt(getTag('v') ?? '1', 10)
  const algorithm = getTag('algo') ?? 'aes-256-gcm'
  const kdf = getTag('kdf') ?? 'hkdf-sha256'

  const transportsTag = event.tags.find(t => t[0] === 'transports')
  const transports = transportsTag ? transportsTag.slice(1) : []

  const clientName = getTag('client')

  let credentialId: Uint8Array
  try {
    credentialId = base64url.decode(credentialIdBase64url)
  } catch {
    throw new KeytrError('Invalid credential ID encoding in "d" tag')
  }

  const mode: KeytrMode = version === KEYTR_KIH_VERSION ? 'kih' : 'prf'

  return {
    credentialIdBase64url,
    credentialId,
    rpId,
    encryptedBlob: event.content,
    version,
    algorithm,
    kdf,
    transports,
    clientName,
    mode,
  }
}
