NIP-79
======

Passkey-Encrypted Private Keys
------------------------------

`draft` `optional`

This NIP defines a method for encrypting Nostr private keys (nsec) using WebAuthn passkeys via the PRF (Pseudo-Random Function) extension, and publishing the encrypted result to relays for cross-device key recovery.

## Motivation

Nostr private key management is a major UX barrier. Users must manually copy their nsec between devices, risking exposure through clipboard, screenshots, or insecure storage. Hardware signers (NIP-46) add complexity. Browser extensions (NIP-07) don't sync across devices.

Passkeys solve this: they sync across devices automatically (iCloud Keychain, Google Password Manager, Windows Hello), require biometric/PIN verification, and are phishing-resistant. By using the PRF extension to derive an encryption key, we can encrypt an nsec and safely publish it to relays. Any device with the synced passkey can decrypt it.

## Overview

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  User Device  │────▶│  Passkey PRF   │────▶│  HKDF-SHA256  │
│  (nsec)       │     │  (32-byte out) │     │  (AES key)    │
└──────────────┘     └───────────────┘     └──────┬───────┘
                                                   │
                                           ┌──────▼───────┐
                                           │  AES-256-GCM  │
                                           │  encrypt nsec  │
                                           └──────┬───────┘
                                                   │
                                           ┌──────▼───────┐
                                           │  kind:30079    │
                                           │  publish to    │
                                           │  relay         │
                                           └──────────────┘
```

## Event Kind

This NIP uses **kind `30079`** (parameterized replaceable event).

Each passkey credential produces a distinct event, identified by the credential ID in the `d` tag. Updating the encryption for the same credential replaces the previous event.

### Event Format

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
  "created_at": <unix-timestamp>,
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

## Encryption Specification

### PRF Extension

The WebAuthn PRF extension (`prf`) is used to derive a deterministic 32-byte output from the authenticator. The same credential + salt always produces the same output, enabling reproducible key derivation.

**PRF Salt** (used in both registration and authentication):
```
eval.first = UTF-8("nostkey-v1")
```

The PRF salt is fixed by this specification. It MUST NOT be changed per-user or per-encryption, as the PRF output must be reproducible across devices.

### Key Derivation

The 32-byte PRF output is not used directly as an encryption key. Instead, HKDF-SHA256 is applied:

```
KEY = HKDF-SHA256(
  ikm    = PRF_OUTPUT,        // 32 bytes from authenticator
  salt   = random(32),        // 32 random bytes, stored in blob
  info   = UTF-8("nostkey nsec encryption v1"),
  length = 32                 // 256-bit AES key
)
```

The random HKDF salt ensures that re-encrypting the same nsec with the same passkey produces different ciphertext.

### AES-256-GCM Encryption

```
IV  = random(12)              // 12 bytes, stored in blob
AAD = UTF-8("nostkey") || VERSION_BYTE || CREDENTIAL_ID_BYTES

CIPHERTEXT = AES-256-GCM(
  key       = KEY,
  iv        = IV,
  plaintext = NSEC_RAW_BYTES, // 32 bytes
  aad       = AAD
)
```

The AAD (Additional Authenticated Data) binds the ciphertext to the specific credential and version, preventing substitution and downgrade attacks.

### Encrypted Blob Format

The `content` field contains a base64-encoded binary blob:

```
Offset  Length  Field
0       1       Version (0x01)
1       12      IV (AES-GCM nonce)
13      32      HKDF salt
45      48      Ciphertext (32-byte nsec + 16-byte GCM auth tag)
─────────────
Total: 93 bytes → ~124 base64 characters
```

## Cross-Client Compatibility

### Shared Relying Party: nostkey.org

To enable the same passkey to work across multiple Nostr clients, all participating clients SHOULD use the shared Relying Party ID: `nostkey.org`.

The `nostkey.org` domain hosts a `.well-known/webauthn` file listing authorized origins per the [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) specification:

```json
{
  "origins": [
    "https://client-a.example.com",
    "https://snort.social",
    "https://primal.net"
  ]
}
```

A passkey registered with `rpId: "nostkey.org"` on any listed origin produces the same PRF output on every listed origin. This enables cross-client decryption without re-registration.

### Standalone Mode

Clients MAY use their own domain as the rpId. In this case, the `rp` tag tells other clients which origin to visit for decryption. This mode is fully decentralized but limits cross-client portability.

## Client Behavior

### Setup Flow

1. Generate or accept a 32-byte nsec
2. Call `navigator.credentials.create()` with PRF extension and `rpId: "nostkey.org"`
3. Verify PRF support via `prf.enabled === true` in extension outputs
4. Extract the 32-byte PRF output from `prf.results.first`
5. Generate random IV (12 bytes) and HKDF salt (32 bytes)
6. Derive AES key via HKDF-SHA256
7. Encrypt nsec with AES-256-GCM
8. Serialize the blob (version + IV + salt + ciphertext)
9. Build and sign a kind:30079 event
10. Publish to relays
11. Zero out PRF output, derived key, and raw nsec from memory

### Login Flow

1. Fetch kind:30079 events for the user's pubkey from relays
2. Parse the event to extract credential ID, rpId, and encrypted blob
3. Call `navigator.credentials.get()` with the credential ID and PRF extension
4. Extract the 32-byte PRF output
5. Deserialize the blob to get IV, HKDF salt, and ciphertext
6. Derive AES key via HKDF-SHA256 using the salt from the blob
7. Decrypt with AES-256-GCM
8. The result is the 32-byte nsec
9. Zero out PRF output and derived key from memory

### Multiple Passkeys

Users SHOULD register multiple passkeys for redundancy. Each passkey produces a separate kind:30079 event with a different `d` tag. Any one passkey can decrypt its corresponding event.

## Password Fallback

When the authenticator does not support the PRF extension, clients SHOULD offer password-based encryption as a fallback, using scrypt + AES-256-GCM (compatible with NIP-49).

Clients MUST clearly indicate whether the key is protected by a passkey or a password.

## Security Considerations

### Passkey Deletion = Permanent Key Loss

If a user deletes their passkey and has no backup, the encrypted nsec is permanently irrecoverable. Clients MUST warn users and SHOULD encourage registering multiple passkeys and keeping a password backup.

### Origin Binding

The PRF output is bound to the rpId. A phishing site cannot derive the correct encryption key even if the user completes the WebAuthn ceremony on a different domain.

### Relay Safety

The encrypted blob is meaningless without the passkey. An attacker with the event still needs the physical authenticator (or synced passkey) and must pass biometric/PIN verification.

### Memory Hygiene

Implementations SHOULD zero out PRF output, derived keys, and decrypted nsec after use.

### No Server Trust Required

This protocol requires no trusted server. The relay is a dumb store. Encryption is end-to-end between the authenticator and the Nostr client.

## Relation to Other NIPs

| NIP | Relation |
|-----|----------|
| NIP-01 | Standard event structure |
| NIP-07 | Browser extensions can integrate nostkey for key import |
| NIP-46 | Alternative: nostkey stores keys locally, NIP-46 delegates signing |
| NIP-49 | Password fallback uses NIP-49-compatible encryption |
