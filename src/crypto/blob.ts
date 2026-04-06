import { BLOB_VERSION, type EncryptedNsecBlob } from '../types.js'
import { BlobParseError } from '../errors.js'

/**
 * Blob binary layout:
 *   [0]       version   (1 byte)
 *   [1..12]   iv        (12 bytes)
 *   [13..44]  hkdfSalt  (32 bytes)
 *   [45..92]  ciphertext (48 bytes: 32 nsec + 16 GCM tag)
 *   Total: 93 bytes
 */
const BLOB_SIZE = 93
const IV_OFFSET = 1
const IV_LENGTH = 12
const SALT_OFFSET = 13
const SALT_LENGTH = 32
const CT_OFFSET = 45
const CT_LENGTH = 48

/** Serialize an EncryptedNsecBlob into a compact binary format */
export function serializeBlob(blob: EncryptedNsecBlob): Uint8Array {
  if (blob.iv.length !== IV_LENGTH) throw new BlobParseError(`IV must be ${IV_LENGTH} bytes`)
  if (blob.hkdfSalt.length !== SALT_LENGTH) throw new BlobParseError(`Salt must be ${SALT_LENGTH} bytes`)
  if (blob.ciphertext.length !== CT_LENGTH) throw new BlobParseError(`Ciphertext must be ${CT_LENGTH} bytes`)

  const out = new Uint8Array(BLOB_SIZE)
  out[0] = blob.version
  out.set(blob.iv, IV_OFFSET)
  out.set(blob.hkdfSalt, SALT_OFFSET)
  out.set(blob.ciphertext, CT_OFFSET)
  return out
}

/** Deserialize a binary blob back into its structured components */
export function deserializeBlob(data: Uint8Array): EncryptedNsecBlob {
  if (data.length !== BLOB_SIZE) {
    throw new BlobParseError(`Expected ${BLOB_SIZE} bytes, got ${data.length}`)
  }

  const version = data[0]
  if (version !== BLOB_VERSION) {
    throw new BlobParseError(`Unsupported blob version: ${version}`)
  }

  return {
    version,
    iv: data.slice(IV_OFFSET, IV_OFFSET + IV_LENGTH),
    hkdfSalt: data.slice(SALT_OFFSET, SALT_OFFSET + SALT_LENGTH),
    ciphertext: data.slice(CT_OFFSET, CT_OFFSET + CT_LENGTH),
  }
}
