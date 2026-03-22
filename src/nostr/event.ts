import { base64url } from '@scure/base'
import { NOSTKEY_EVENT_KIND, type NostkeyEventTemplate, type NostkeyCredential } from '../types.js'
import { NostkeyError } from '../errors.js'

interface BuildEventOptions {
  credential: NostkeyCredential
  encryptedBlob: string
  clientName?: string
}

/** Build an unsigned kind:30079 event template for a passkey-encrypted nsec */
export function buildNostkeyEvent(options: BuildEventOptions): NostkeyEventTemplate {
  const { credential, encryptedBlob, clientName } = options

  const tags: string[][] = [
    ['d', credential.credentialIdBase64url],
    ['rp', credential.rpId],
    ['algo', 'aes-256-gcm'],
    ['kdf', 'hkdf-sha256'],
    ['v', '1'],
  ]

  if (clientName) {
    tags.push(['client', clientName])
  }

  if (credential.transports.length > 0) {
    tags.push(['transports', ...credential.transports])
  }

  return {
    kind: NOSTKEY_EVENT_KIND,
    content: encryptedBlob,
    tags,
    created_at: Math.floor(Date.now() / 1000),
  }
}

interface ParsedNostkeyEvent {
  credentialIdBase64url: string
  credentialId: Uint8Array
  rpId: string
  encryptedBlob: string
  version: number
  algorithm: string
  kdf: string
  transports: string[]
  clientName?: string
}

/** Parse a kind:30079 event to extract credential info and encrypted blob */
export function parseNostkeyEvent(event: {
  kind: number
  content: string
  tags: string[][]
}): ParsedNostkeyEvent {
  if (event.kind !== NOSTKEY_EVENT_KIND) {
    throw new NostkeyError(`Expected kind ${NOSTKEY_EVENT_KIND}, got ${event.kind}`)
  }

  const getTag = (name: string): string | undefined =>
    event.tags.find(t => t[0] === name)?.[1]

  const credentialIdBase64url = getTag('d')
  if (!credentialIdBase64url) {
    throw new NostkeyError('Missing "d" tag (credential ID)')
  }

  const rpId = getTag('rp')
  if (!rpId) {
    throw new NostkeyError('Missing "rp" tag')
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
    throw new NostkeyError('Invalid credential ID encoding in "d" tag')
  }

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
  }
}
