NIP-K1
======

Passkey-Vaulted Private Keys
-----------------------------

`draft` `optional`

This NIP defines a method for managing Nostr private keys using WebAuthn passkeys as a cryptographic vault. The encryption key for a user's Nostr identity is embedded in the WebAuthn credential's `user.id` (user handle) field, creating a **split-knowledge** system where neither the storage layer nor the authenticator alone can access the private key.

## Motivation

Nostr private key management is a major UX barrier. Users must manually copy their `nsec` between devices, risking exposure through clipboard, screenshots, or insecure storage. Hardware signers (NIP-46) add complexity. Browser extensions (NIP-07) don't sync across devices.

WebAuthn passkeys solve the transport problem — they sync across devices automatically via iCloud Keychain, Google Password Manager, and similar platform credential managers. They require biometric or PIN verification, and are phishing-resistant by design.

This NIP uses the WebAuthn `user.id` field to embed both the user's public key and a symmetric encryption key inside the passkey credential itself. This approach:

- **Works on all WebAuthn authenticators** — unlike the PRF extension, the `user.id` field is part of the base WebAuthn specification and is universally supported.
- **Creates a split-knowledge model** — the relay stores the encrypted private key but cannot decrypt it; the authenticator holds the decryption key but only releases it after biometric/PIN verification.
- **Requires a single gesture** — one biometric tap to authenticate and recover the private key.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        SETUP                                │
│                                                             │
│  Generate nsec ──► Generate export key (random 32B)         │
│       │                    │                                │
│       │              ┌─────▼──────┐                         │
│       │              │  Pack into  │                        │
│       │              │  user.id    │ ◄── npub (32B)         │
│       │              │  (64 bytes) │ ◄── export key (32B)   │
│       │              └─────┬──────┘                         │
│       │                    │                                │
│       ▼                    ▼                                │
│  AES-256-GCM ◄──── export key        Register passkey      │
│  encrypt nsec                         with user.id          │
│       │                                                     │
│       ▼                                                     │
│  kind:30079 event ──► publish to relays                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        LOGIN                                │
│                                                             │
│  Authenticate passkey (biometric/PIN)                       │
│       │                                                     │
│       ▼                                                     │
│  userHandle returned by authenticator                       │
│       │                                                     │
│       ├── bytes 0–31:  npub (hex public key)                │
│       └── bytes 32–63: export key                           │
│                │                                            │
│                ▼                                            │
│  Fetch kind:30079 events for npub from relays               │
│       │                                                     │
│       ▼                                                     │
│  AES-256-GCM decrypt ◄── export key                        │
│       │                                                     │
│       ▼                                                     │
│  Recovered nsec                                             │
└─────────────────────────────────────────────────────────────┘
```

## Specification

### User Handle Format

The WebAuthn credential's `user.id` field stores exactly **64 bytes**:

```
Offset  Length  Field
0       32      Nostr public key (raw 32-byte x-only pubkey, not bech32)
32      32      Export key (random 256-bit symmetric key)
────────────
Total: 64 bytes
```

The 64-byte limit matches the [WebAuthn specification's maximum `user.id` length](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).

The **export key** is a cryptographically random 256-bit value generated once during registration. It serves as the AES-256-GCM encryption key for the user's Nostr private key.

### Registration (Setup)

1. Generate a random 32-byte Nostr private key (nsec).
2. Derive the 32-byte public key (npub) from the nsec.
3. Generate a cryptographically random 32-byte **export key**.
4. Encrypt the nsec using the export key (see [Encryption](#encryption)) → produces an encrypted blob.
5. Pack `npub (32 bytes) || export key (32 bytes)` → 64 bytes → set as `user.id`.
6. Register a WebAuthn passkey with the following options:

```javascript
{
  challenge: serverOrClientChallenge,
  rp: {
    name: "Relying Party Name",
    id: rpId                              // e.g., "keytr.org"
  },
  user: {
    id: packedUserHandle,                 // 64 bytes: npub + export key
    name: userIdentifier,                 // e.g., "npub1...@keytr.org"
    displayName: userDisplayName
  },
  pubKeyCredParams: [
    { type: "public-key", alg: -7 },     // ES256 (P-256 ECDSA)
    { type: "public-key", alg: -257 }    // RS256 (RSASSA-PKCS1-v1_5)
  ],
  authenticatorSelection: {
    userVerification: "required",
    residentKey: "required",
    requireResidentKey: true
  },
  attestation: "none"
}
```

7. Build a kind:30079 event containing the encrypted blob (see [Event Format](#event-format)).
8. Sign the event with the nsec and publish to Nostr relays.
9. Zero the nsec and export key from memory.

Clients SHOULD support both ES256 (alg: -7) and RS256 (alg: -257) to maximize authenticator compatibility. Discoverable credentials (`residentKey: "required"`) and user verification (`userVerification: "required"`) are REQUIRED — these ensure the passkey is a true synced passkey and that biometric/PIN is always enforced.

### Authentication (Login)

1. Call `navigator.credentials.get()`:

```javascript
{
  challenge: clientChallenge,             // random bytes
  rpId: rpId,                             // from event's "rp" tag
  userVerification: "required",
  allowCredentials: []                    // empty = discoverable credential
}
```

2. Extract `userHandle` from the `AuthenticatorAssertionResponse`.
3. Unpack the user handle:
   - Bytes 0–31: Nostr public key (raw 32-byte x-only pubkey)
   - Bytes 32–63: Export key
4. Fetch kind:30079 events for the extracted public key from Nostr relays.
5. Select the event whose `d` tag matches the credential ID from the authenticator response.
6. Parse the event and extract the encrypted blob from the `content` field.
7. Decrypt the nsec using the export key (see [Decryption](#decryption)).
8. Verify that the public key derived from the decrypted nsec matches the npub from the user handle.
9. Zero the export key from memory.

Using `allowCredentials: []` (empty array) triggers the platform's passkey picker, allowing the user to select which identity to authenticate with. This is the recommended approach for login.

### Encryption

The export key is used directly as the AES-256-GCM key. No key derivation function is applied — the export key is already a cryptographically random 256-bit value.

```
IV  = random(12)                          // 12-byte nonce
AAD = CREDENTIAL_ID_BYTES                 // raw credential ID

CIPHERTEXT = AES-256-GCM(
  key       = EXPORT_KEY,                 // 32 bytes from user.id
  iv        = IV,
  plaintext = NSEC_RAW_BYTES,             // 32 bytes
  aad       = AAD
)
```

The AAD (Additional Authenticated Data) binds the ciphertext to the specific WebAuthn credential ID, preventing an attacker from substituting one encrypted blob for another.

### Decryption

```
1. Deserialize the blob to extract version, IV, and ciphertext.
2. Reconstruct AAD from the credential ID.
3. Decrypt:

NSEC_RAW_BYTES = AES-256-GCM-DECRYPT(
  key        = EXPORT_KEY,
  iv         = IV,
  ciphertext = CIPHERTEXT,
  aad        = CREDENTIAL_ID_BYTES
)
```

If the wrong passkey is used, the export key will not match, and AES-GCM decryption will fail with an authentication error. If the credential ID does not match, the AAD mismatch causes the same failure.

### Encrypted Blob Format

The `content` field of the Nostr event contains a base64-encoded binary blob:

```
Offset  Length  Field
0       1       Version (0x01)
1       12      IV (AES-GCM nonce)
13      48      Ciphertext (32-byte nsec + 16-byte GCM auth tag)
────────────
Total: 61 bytes → ~82 base64 characters
```

Implementations MUST reject blobs where:
- The version byte is not `0x01`
- The total length is not exactly 61 bytes

### Event Kind

This NIP uses **kind `30079`** (parameterized replaceable event).

Each passkey credential produces a distinct event, identified by the credential ID in the `d` tag. Re-encrypting with the same passkey replaces the previous event.

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
    ["scheme", "passkey-vault"],
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
| `d` | Yes | Base64url-encoded WebAuthn credential ID. Makes this a parameterized replaceable event — re-encryption with the same passkey replaces the old event. |
| `rp` | Yes | WebAuthn Relying Party ID (domain). Clients need this to know which rpId to use for the authentication ceremony. |
| `algo` | Yes | Encryption algorithm. MUST be `aes-256-gcm`. |
| `scheme` | Yes | Key management scheme. MUST be `passkey-vault` for this NIP. Distinguishes from other encrypted key storage approaches. |
| `v` | Yes | Blob format version. Currently `1`. |
| `transports` | No | WebAuthn authenticator transports (e.g., `internal`, `hybrid`, `usb`, `ble`, `nfc`). Helps clients optimize the authentication UX. |
| `client` | No | Name of the client that created this event. Informational only. |

## Cross-Client Compatibility

### Federated Gateway Model

WebAuthn passkeys are bound to an **rpId** (a domain). A passkey created with `rpId: "app-a.com"` will not be usable on `app-b.com`. Without a solution, every Nostr client would need its own passkey registration, defeating the purpose.

WebAuthn's [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) specification solves this. A gateway domain hosts a `/.well-known/webauthn` file declaring which origins are authorized to use its passkeys:

```json
{
  "origins": [
    "https://client-a.example.com",
    "https://client-b.example.com"
  ]
}
```

A passkey registered with a gateway's rpId on **any** listed origin works on **every** listed origin. The authenticator returns the same credential and user handle regardless of which authorized origin triggers the ceremony.

The model is **federated**: there is no single canonical gateway. Multiple independent domains can each host their own `.well-known/webauthn` and authorize their own set of Nostr clients:

| Gateway | Operator | Hosting | Authorized Origins |
|---------|----------|---------|-------------------|
| `keytr.org` | sovIT | Cloudflare Pages | nostkey.org, bies.sovit.xyz, gitvid.sovit.xyz, nostrbook.net |
| `nostkey.org` | sovIT | GitHub Pages | keytr.org, bies.sovit.xyz, gitvid.sovit.xyz, nostrbook.net |
| `keys.example.org` | Self-hosted | Any | personal-client.example.org |

Users can register passkeys against **multiple gateways**, producing separate kind:30079 events for each. Losing access to one gateway does not affect events encrypted under other rpIds.

### Cross-Gateway Trust

Gateways MAY list each other as authorized origins, enabling passkeys registered under one gateway's rpId to be used from another gateway's domain. For example, if `keytr.org/.well-known/webauthn` includes `https://nostkey.org`, a user on `nostkey.org` can authenticate with a passkey bound to `rpId: "keytr.org"`.

The authentication flow for cross-gateway usage:

1. Client on origin B calls `navigator.credentials.get()` with `rpId` set to gateway A's domain
2. Browser fetches `https://gateway-a/.well-known/webauthn`
3. Browser verifies origin B is listed in the `origins` array
4. Authenticator runs the ceremony using gateway A's rpId — returns the same credential and user handle

This requires browser support for [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) (Chrome 128+, Safari 18+).

### Adding Client Origins to a Gateway

To authorize a new origin for an existing gateway, add the client's full origin (e.g., `https://client.example.com`) to the gateway's `/.well-known/webauthn` origins array. No changes are needed on the client side — the browser handles validation automatically.

### Standalone Mode

Clients MAY use their own domain as the rpId instead of (or in addition to) a gateway. In standalone mode:

- The `rp` tag in the event tells other clients which origin to visit for decryption.
- Only the client's own domain can decrypt the event.
- This requires no coordination with any gateway.

### Recommended Strategy

For maximum portability, clients SHOULD:

1. Register against at least one gateway (e.g., `keytr.org`) for cross-client access.
2. Optionally register a standalone credential under the client's own rpId as a backup.
3. Support decryption of events encrypted under any rpId the client is authorized for.

## Security Model

### Split-Knowledge Design

The architecture ensures that no single party can access the user's Nostr private key:

| Component | Has Access To | Cannot Access |
|-----------|--------------|---------------|
| **Relay** | Encrypted blob (kind:30079 event) | Export key — cannot decrypt |
| **Passkey Authenticator** | Export key stored in `user.id` | Only releases after biometric/PIN verification |
| **Neither Alone** | — | The actual Nostr private key (nsec) |

Both the relay's encrypted event **and** the authenticator's export key are required to reconstruct the private key. This is conceptually a 2-of-2 secret sharing scheme.

### Origin Binding

The passkey ceremony is bound to the rpId. A phishing site on a different domain cannot trigger the passkey — the browser enforces origin checks before the authenticator is contacted.

### User Verification

Every operation requires `userVerification: "required"`, meaning biometric (Face ID, Touch ID, fingerprint) or PIN verification. An attacker with physical access to the device still cannot extract the export key without passing user verification.

### Passkey Sync Security

When passkeys sync across devices (via iCloud Keychain, Google Password Manager, etc.), the `user.id` — including the export key — syncs with them. The security of the export key therefore depends on the security of the credential manager:

- **iCloud Keychain**: End-to-end encrypted, protected by device passcode and Apple ID.
- **Google Password Manager**: Encrypted with the user's Google account credentials.
- **FIDO2 hardware keys**: No sync; export key is device-bound.

Clients SHOULD inform users that the security of their Nostr identity is tied to the security of their passkey provider.

### Relay Safety

The encrypted blob published to relays is meaningless without the export key. An attacker who obtains the event from a relay still needs:

1. Access to the user's synced passkey (or the physical authenticator)
2. The ability to pass biometric/PIN verification

Offline brute-force is infeasible — AES-256-GCM with a random 256-bit key has no known practical attack.

### Passkey Deletion = Permanent Key Loss

If a user deletes all passkeys that hold the export key, and has no other backup of their nsec, the encrypted data on relays becomes permanently irrecoverable. Clients MUST warn users about this and SHOULD encourage:

- Registering multiple passkeys (e.g., phone + laptop + hardware key)
- Keeping a separate backup of the nsec (e.g., NIP-49 encrypted backup)

### Memory Hygiene

Implementations SHOULD zero the export key, decrypted nsec, and any intermediate key material from memory after use. In JavaScript, overwrite `Uint8Array` contents with zeros in a `finally` block.

### Server-Side Considerations

If an implementation uses a server-side component (e.g., for challenge generation or encrypted data storage), the `userHandle` — which contains the export key — is returned as part of the `AuthenticatorAssertionResponse`. Implementations MUST extract the export key **client-side** and MUST NOT send the raw user handle to any server. Only the npub (bytes 0–31) should be transmitted for account identification.

## Multiple Passkeys

Users SHOULD register multiple passkeys for redundancy. Each passkey:

- Has its own credential ID
- Contains the same npub but a **different** export key in its `user.id`
- Produces a separate kind:30079 event with a different `d` tag
- Can independently decrypt its corresponding event

To register an additional passkey for an existing identity:

1. Decrypt the nsec using any existing passkey
2. Generate a new random export key
3. Re-encrypt the nsec with the new export key
4. Pack the same npub + new export key into the new passkey's `user.id`
5. Register the new passkey
6. Publish the new kind:30079 event

## Acknowledgments

The passkey-vaulted key management approach described in this NIP was pioneered by [BitTasker](https://bittasker.com), who first implemented the split-knowledge model using the WebAuthn `user.id` field to secure Nostr private keys in production.

## Relation to Other NIPs

| NIP | Relation |
|-----|----------|
| NIP-01 | Standard event structure used for kind:30079 events |
| NIP-07 | Browser extension signers can integrate NIP-K1 for key import/export |
| NIP-46 | Alternative approach: NIP-46 delegates signing to a remote signer; NIP-K1 stores keys locally |
| NIP-49 | Can be used as a complementary backup method (password-encrypted nsec for offline storage) |
