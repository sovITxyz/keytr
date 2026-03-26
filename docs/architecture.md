# keytr Architecture

## The Problem

Nostr private key management is a major UX barrier. Users must manually copy their `nsec` between devices, risking exposure through clipboard, screenshots, or insecure storage. Hardware signers (NIP-46) add complexity. Browser extensions (NIP-07) don't sync across devices.

## The Solution

keytr uses **WebAuthn passkeys** — which already sync across devices via iCloud Keychain, Google Password Manager, etc. — to **encrypt your nsec** and publish the ciphertext to Nostr relays. Any device that has the synced passkey can decrypt it. No trusted server. No password to remember.

## Overview

```
User Device (nsec)
       │
       ▼
  Passkey PRF Extension ──► 32-byte deterministic output
       │
       ▼
  HKDF-SHA256 ──► 256-bit AES key
       │
       ▼
  AES-256-GCM ──► encrypted blob (93 bytes)
       │
       ▼
  kind:30079 Nostr event ──► published to relays
```

The system has four layers: **crypto**, **webauthn**, **nostr**, and **high-level flows**.

---

## Layer 1: Cryptography

### Key Derivation

The passkey's PRF extension outputs a raw 32-byte value. This is NOT used directly as an encryption key. Instead, it goes through HKDF-SHA256:

```
KEY = HKDF-SHA256(
  ikm    = PRF output       (32 bytes from authenticator)
  salt   = random(32)       (fresh per encryption, stored in blob)
  info   = "keytr nsec encryption v1"
  length = 32               (256-bit AES key)
)
```

The random salt means re-encrypting the same nsec with the same passkey produces **different ciphertext** every time. This prevents an observer from detecting re-encryption or key reuse.

Source: `src/crypto/kdf.ts`

### Encryption

Given the nsec bytes, PRF output, and credential ID:

1. Generate 12-byte random IV (AES-GCM nonce)
2. Generate 32-byte random HKDF salt
3. Derive AES-256 key via HKDF (above)
4. Build AAD: `"keytr" || 0x01 || credentialId` — this binds the ciphertext to a specific credential and version, preventing substitution/downgrade attacks
5. Encrypt: `AES-256-GCM(key, iv, nsec, aad)` → 48 bytes (32-byte nsec + 16-byte auth tag)
6. Serialize into a 93-byte blob, then base64-encode

Source: `src/crypto/encrypt.ts`

### Decryption

The reverse: base64-decode → deserialize → re-derive the same key using the stored HKDF salt → AES-GCM decrypt with reconstructed AAD → recover 32-byte nsec. If the wrong passkey or wrong credential ID is used, the AAD mismatch causes GCM to reject the ciphertext.

Source: `src/crypto/decrypt.ts`

### Blob Binary Format

```
Offset  Length  Field
0       1       Version byte (0x01)
1       12      IV (AES-GCM nonce)
13      32      HKDF salt
45      48      Ciphertext (32-byte nsec + 16-byte GCM auth tag)
────────────
Total: 93 bytes → ~124 base64 characters
```

`serializeBlob()` packs the `EncryptedNsecBlob` struct into this binary layout. `deserializeBlob()` unpacks it with validation (checks version, total length).

Source: `src/crypto/blob.ts`

---

## Layer 2: WebAuthn / Passkey Integration

### The PRF Extension

The critical piece. WebAuthn's PRF extension lets a passkey produce a **deterministic 32-byte output** given a fixed salt. keytr uses the salt `"keytr-v1"` (as an ArrayBuffer) for both registration and authentication. This salt is fixed by spec — it MUST NOT vary per user, because the PRF output must be reproducible on any device that has the synced passkey.

Key functions:

- `prfRegistrationExtension()` — builds the `extensions.prf` config for `navigator.credentials.create()`
- `prfAuthenticationExtension()` — builds it for `navigator.credentials.get()`
- `extractPrfOutput(extensionResults)` — pulls out `prf.results.first` (32 bytes)
- `isPrfEnabled(extensionResults)` — checks `prf.enabled === true`

Source: `src/webauthn/prf.ts`

### Registration

`registerPasskey(options)` does:

1. Generate random 32-byte user ID and challenge
2. Build `CredentialCreationOptions`:
   - `rpId`: defaults to `"keytr.org"` (or custom domain)
   - Algorithms: ES256 (-7), RS256 (-257)
   - `authenticatorSelection`: resident key required, user verification required
   - `extensions`: PRF with salt `"keytr-v1"`
3. Call `navigator.credentials.create()`
4. Verify `prf.enabled === true` in the response — throws `PrfNotSupportedError` if not
5. Extract the 32-byte PRF output from `prf.results.first`
6. Extract credential ID (raw bytes + base64url), rpId, transports
7. Return `{ credential: KeytrCredential, prfOutput: Uint8Array }`

Source: `src/webauthn/register.ts`

### Authentication

`authenticatePasskey(options)` does:

1. Build `CredentialRequestOptions`:
   - `rpId`: must match what was used at registration
   - Random challenge
   - `allowCredentials`: the specific credential ID from the event's `d` tag
   - `extensions`: PRF with salt `"keytr-v1"`
2. Call `navigator.credentials.get()` — triggers biometric/PIN
3. Extract 32-byte PRF output
4. Return the PRF output for decryption

Source: `src/webauthn/authenticate.ts`

### Support Detection

`checkPrfSupport()` checks:

- `window.PublicKeyCredential` exists
- Platform authenticator availability
- Notes that full PRF detection is only possible at registration time (reported optimistically)

Returns `{ supported: boolean, platformAuthenticator: boolean, reason?: string }`

Source: `src/webauthn/support.ts`

---

## Layer 3: Nostr Integration

### Key Utilities

Wrappers around `nostr-tools/pure`:

- `generateNsec()` — random 32-byte private key
- `nsecToPublicKey()` / `nsecToPublicKeyHex()` — derive public key
- `encodeNsec()` / `decodeNsec()` — bech32 encode/decode with `nsec` prefix
- `encodeNpub()` / `decodeNpub()` — bech32 with `npub` prefix
- `nsecToNpub()` / `nsecToHexPubkey()` — convenience shortcuts

Source: `src/nostr/keys.ts`

### Event Format

keytr uses **kind 30079** (parameterized replaceable event):

```json
{
  "kind": 30079,
  "pubkey": "<user's hex public key>",
  "content": "<base64-encoded encrypted blob>",
  "tags": [
    ["d", "<credential-id-base64url>"],
    ["rp", "<relying-party-id>"],
    ["algo", "aes-256-gcm"],
    ["kdf", "hkdf-sha256"],
    ["v", "1"],
    ["transports", "internal", "hybrid", "..."],
    ["client", "<client-name>"]
  ],
  "created_at": "<unix-timestamp>",
  "id": "...",
  "sig": "..."
}
```

### Tag Definitions

| Tag | Required | Description |
|-----|----------|-------------|
| `d` | Yes | Base64url-encoded WebAuthn credential ID. Makes this a parameterized replaceable event. |
| `rp` | Yes | WebAuthn Relying Party ID (domain). Clients need this to know which origin to use for decryption. |
| `algo` | Yes | Encryption algorithm. MUST be `aes-256-gcm`. |
| `kdf` | Yes | Key derivation function. MUST be `hkdf-sha256`. |
| `v` | Yes | Blob format version. Currently `1`. |
| `transports` | No | WebAuthn authenticator transports (e.g., `internal`, `hybrid`, `usb`, `ble`, `nfc`). |
| `client` | No | Name of the client that created this event. |

The `d` tag is the credential ID (base64url), making this a **parameterized replaceable event** — re-encrypting with the same passkey replaces the old event on relays.

Source: `src/nostr/event.ts`

### Relay Operations

- `publishKeytrEvent(signedEvent, relayUrls)` — publishes to each relay sequentially; only throws if ALL relays fail
- `fetchKeytrEvents(pubkey, relayUrls)` — subscribes to kind:30079 events for a pubkey across relays with a 5-second timeout, deduplicates by event ID

Source: `src/nostr/relay.ts`

---

## Layer 4: High-Level Flows

### Setup (New User / New Passkey)

```typescript
const result = await setupKeytr({
  userName: 'alice',
  userDisplayName: 'Alice',
  rpId: 'keytr.org',      // optional, defaults to keytr.org
  clientName: 'my-app',   // optional
})
// result: { credential, encryptedBlob, eventTemplate, nsecBytes, npub }
```

Internally:

1. `generateNsec()` → 32-byte nsec
2. `nsecToNpub(nsec)` → bech32 public key
3. `registerPasskey()` → credential + PRF output
4. `encryptNsec({ nsecBytes, prfOutput, credentialId })` → base64 blob
5. Zero out PRF output (in `finally` block)
6. `buildKeytrEvent({ credential, encryptedBlob })` → unsigned event template
7. Return everything

The caller is responsible for: signing the event with the nsec, publishing it to relays, and zeroing `nsecBytes` after use.

Source: `src/index.ts`

### Login (Key Recovery on New Device)

```typescript
const { nsecBytes, npub } = await loginWithKeytr(event)
```

Internally:

1. `parseKeytrEvent(event)` → extract credential ID, rpId, blob
2. `authenticatePasskey({ credentialId, rpId, transports })` → PRF output (triggers biometric)
3. `decryptNsec({ encryptedBlob, prfOutput, credentialId })` → 32-byte nsec
4. Zero out PRF output (in `finally` block)
5. `nsecToNpub(nsec)` → derive npub
6. Return `{ nsecBytes, npub }`

Source: `src/index.ts`

---

## Federated Gateway Model

### The Problem

WebAuthn passkeys are bound to an **rpId** (a domain). A passkey created on `primal.net` won't produce a PRF output on `snort.social` — the domains don't match. Without a solution, every Nostr client would need its own passkey registration, defeating the purpose.

### The Solution: Related Origin Requests

WebAuthn's [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) spec lets a domain host a `/.well-known/webauthn` file declaring which origins are authorized:

```json
// https://keytr.org/.well-known/webauthn
{
  "origins": [
    "https://primal.net",
    "https://snort.social",
    "https://coracle.social"
  ]
}
```

A passkey registered with `rpId: "keytr.org"` on **any** listed origin produces the **same PRF output** on **every** listed origin. This means:

1. User registers a passkey on Primal → encrypted nsec event published
2. User opens Snort on a new device → Snort fetches the event, triggers the same passkey, gets the same PRF output → decrypts the nsec

### Federated, Not Centralized

There is no single gateway. Anyone can run one:

| Gateway | Operator | Authorized Origins |
|---------|----------|--------------------|
| `keytr.org` | sovIT | primal.net, coracle.social, ... |
| `passkey.nostr.com` | Community X | nostrudel.ninja, snort.social, ... |
| `keys.example.org` | Self-hosted | personal-client.example.org |

Users can register passkeys against **multiple gateways**, producing separate kind:30079 events for each. Losing access to one gateway doesn't affect events encrypted under other rpIds.

### Standalone Mode

A client can skip gateways entirely and use its own domain as the rpId. Only that domain can decrypt. The `rp` tag in the event tells other clients which origin to visit if they want to attempt decryption.

### Recommended Strategy

1. Register against at least one gateway (e.g., `keytr.org`) for portability
2. Optionally register a standalone credential as backup
3. Support decryption of events under any rpId the client is authorized for

---

## Security Model

| Property | Mechanism |
|----------|-----------|
| **Hardware-bound key** | PRF output requires physical authenticator + biometric/PIN — unlike passwords, can't be phished or brute-forced |
| **Origin-bound** | PRF output tied to rpId — phishing sites on different domains get a different (useless) PRF output |
| **AAD binding** | Ciphertext authenticated against credential ID + version — prevents ciphertext substitution or downgrade |
| **Unique ciphertexts** | Random IV + random HKDF salt → re-encrypting same nsec produces different output |
| **No server trust** | Relay is a dumb store. All crypto is end-to-end between the authenticator and the client |
| **Memory hygiene** | PRF output and derived keys zeroed after use (in `finally` blocks) |
| **Passkey deletion = permanent loss** | If all passkeys deleted with no backup, nsec is irrecoverable. Multiple passkeys recommended |

### Password Fallback (Disabled)

The code exists in `src/fallback/password.ts` (scrypt + AES-256-GCM, NIP-49 compatible) but is **not exported** from the public API. Reason: password-encrypted blobs on relays can be brute-forced offline. Will be re-enabled only for local-only storage with entropy enforcement.

---

## Error Hierarchy

All errors extend `KeytrError`:

```
KeytrError
├── PrfNotSupportedError   — authenticator doesn't support PRF
├── EncryptionError        — AES-GCM encryption failed
├── DecryptionError        — wrong passkey or corrupted blob
├── BlobParseError         — invalid binary format
├── WebAuthnError          — navigator.credentials call failed
└── RelayError             — all relays failed to publish/fetch
```

Source: `src/errors.ts`

---

## Constants

```
KEYTR_VERSION    = 1
KEYTR_EVENT_KIND = 30079
PRF_SALT         = UTF-8("keytr-v1")
HKDF_INFO        = "keytr nsec encryption v1"
DEFAULT_RP_ID    = "keytr.org"
DEFAULT_RP_NAME  = "keytr"
```

Source: `src/types.ts`

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/ciphers` | AES-256-GCM |
| `@noble/hashes` | HKDF-SHA256, SHA256, CSPRNG |
| `@scure/base` | Base64, Base64url, Bech32 |
| `nostr-tools` | Key generation, relay connections |

All crypto libraries are from the `@noble`/`@scure` family (audited, pure JS, no native dependencies).

---

## Project Structure

```
src/
├── index.ts              — public API + setupKeytr/loginWithKeytr
├── types.ts              — interfaces, constants
├── errors.ts             — error classes
├── crypto/
│   ├── encrypt.ts        — encryptNsec()
│   ├── decrypt.ts        — decryptNsec()
│   ├── kdf.ts            — deriveKey() via HKDF
│   └── blob.ts           — serialize/deserialize 93-byte blob
├── webauthn/
│   ├── register.ts       — registerPasskey()
│   ├── authenticate.ts   — authenticatePasskey()
│   ├── prf.ts            — PRF extension helpers
│   └── support.ts        — checkPrfSupport()
├── nostr/
│   ├── keys.ts           — nsec/npub encode/decode
│   ├── event.ts          — build/parse kind:30079
│   └── relay.ts          — publish/fetch events
└── fallback/
    └── password.ts       — disabled password encryption
```

---

## Public API

### Types

```typescript
KeytrCredential, EncryptedNsecBlob, KeytrEventTemplate,
EncryptOptions, DecryptOptions, PrfSupportInfo,
RegisterOptions, AuthenticateOptions, KeytrBundle
```

### High-Level

```typescript
setupKeytr(options)      // Full registration flow
loginWithKeytr(event)    // Full login/recovery flow
```

### Crypto

```typescript
encryptNsec(options)     // Encrypt nsec with PRF output
decryptNsec(options)     // Decrypt nsec from blob
deriveKey(prf, salt)     // HKDF key derivation
serializeBlob(blob)      // Pack to binary
deserializeBlob(bytes)   // Unpack from binary
```

### WebAuthn

```typescript
checkPrfSupport()                  // Detect PRF capability
registerPasskey(options)           // Create passkey + get PRF
authenticatePasskey(options)       // Assert passkey + get PRF
```

### Nostr

```typescript
generateNsec()                     // Random private key
nsecToPublicKey(nsec)              // Derive public key
encodeNsec(bytes) / decodeNsec(s)  // Bech32 nsec
encodeNpub(bytes) / decodeNpub(s)  // Bech32 npub
nsecToNpub(bytes)                  // Shortcut
nsecToHexPubkey(bytes)             // Hex public key
buildKeytrEvent(options)           // Build kind:30079
parseKeytrEvent(event)             // Parse kind:30079
publishKeytrEvent(event, relays)   // Publish to relays
fetchKeytrEvents(pubkey, relays)   // Fetch from relays
```
