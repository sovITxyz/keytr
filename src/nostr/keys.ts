import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { bech32 } from '@scure/base'
import { hexToBytes } from '@noble/hashes/utils'

const NSEC_PREFIX = 'nsec'
const NPUB_PREFIX = 'npub'

/** Generate a random 32-byte Nostr private key */
export function generateNsec(): Uint8Array {
  return generateSecretKey()
}

/** Derive the hex public key from a 32-byte private key */
export function nsecToPublicKeyHex(nsecBytes: Uint8Array): string {
  return getPublicKey(nsecBytes)
}

/** Derive the public key bytes from a 32-byte private key */
export function nsecToPublicKey(nsecBytes: Uint8Array): Uint8Array {
  return hexToBytes(getPublicKey(nsecBytes))
}

/** Encode a 32-byte private key as bech32 nsec */
export function encodeNsec(nsecBytes: Uint8Array): string {
  const words = bech32.toWords(nsecBytes)
  return bech32.encode(NSEC_PREFIX as `${string}1${string}`, words, 1500)
}

/** Decode a bech32 nsec string to 32-byte raw key */
export function decodeNsec(nsec: string): Uint8Array {
  const { prefix, words } = bech32.decode(nsec as `${string}1${string}`, 1500)
  if (prefix !== NSEC_PREFIX) {
    throw new Error(`Expected nsec prefix, got: ${prefix}`)
  }
  return new Uint8Array(bech32.fromWords(words))
}

/** Encode a 32-byte public key as bech32 npub */
export function encodeNpub(pubkeyBytes: Uint8Array): string {
  const words = bech32.toWords(pubkeyBytes)
  return bech32.encode(NPUB_PREFIX as `${string}1${string}`, words, 1500)
}

/** Decode a bech32 npub string to 32-byte raw public key */
export function decodeNpub(npub: string): Uint8Array {
  const { prefix, words } = bech32.decode(npub as `${string}1${string}`, 1500)
  if (prefix !== NPUB_PREFIX) {
    throw new Error(`Expected npub prefix, got: ${prefix}`)
  }
  return new Uint8Array(bech32.fromWords(words))
}

/** Get npub string from nsec bytes */
export function nsecToNpub(nsecBytes: Uint8Array): string {
  const pubkey = nsecToPublicKey(nsecBytes)
  return encodeNpub(pubkey)
}

/** Get hex-encoded public key from nsec bytes */
export function nsecToHexPubkey(nsecBytes: Uint8Array): string {
  return getPublicKey(nsecBytes)
}
