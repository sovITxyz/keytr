NIP-K2
======

Passkey-Derived Private Keys (Passseeds)
-----------------------------------------

`draft` `optional`

This NIP defines a method for deterministically deriving a Nostr private key from a WebAuthn passkey's PRF output. Unlike NIP-K1 — which encrypts an existing nsec and stores the ciphertext on relays — NIP-K2 uses the passkey itself as the seed. The nsec is derived on demand from the PRF output; no encrypted blob is stored or fetched.

## Motivation

NIP-K1 solved the key-transport problem: one biometric tap to decrypt a synced nsec from a relay. But it still requires relay infrastructure for key recovery and assumes the user has (or generates) a random nsec to encrypt.

For new users, this adds unnecessary steps. A first-time Nostr user must:

1. Generate a random nsec
2. Register a passkey
3. Encrypt the nsec
4. Publish the ciphertext to relays
5. Hope those relays stay available for future login

NIP-K2 collapses this to a single step: **register a passkey, derive your identity**. The passkey IS the identity — no relay needed for key material, no encrypted blob to manage, no ciphertext to protect.

### Use Cases

- **Instant onboarding** — new users get a Nostr identity in one biometric tap, zero relay dependency
- **Offline-first** — derived keys work without any network; the relay is optional
- **Disposable identities** — quick burner identities with no relay footprint
- **Minimal-trust environments** — the key never exists in encrypted form on any external storage

### Tradeoffs vs NIP-K1

| | NIP-K1 | NIP-K2 |
|---|---|---|
| nsec origin | Random (or imported), then encrypted | Deterministically derived from PRF |
| Relay dependency | Required for key recovery | Optional (marker event only) |
| Existing identity | Yes — encrypt any nsec | No — nsec is dictated by the passkey |
| Recovery data | 93-byte encrypted blob on relay | Nothing — the passkey is the key |
| rpId portability | Same nsec encrypted under multiple rpIds | Different rpId = different nsec |
| Key backup | Ciphertext on relay + NIP-49 | Must use NIP-K1 or NIP-49 as escape hatch |

NIP-K1 and NIP-K2 are complementary. K1 serves users with existing identities who need cross-device sync. K2 serves new users and use cases where simplicity and relay independence matter most.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     PASSSEED SETUP                          │
│                                                             │
│  Register passkey with PRF extension                        │
│       │                                                     │
│       ▼                                                     │
│  PRF output (32 bytes)                                      │
│       │                                                     │
│       ▼                                                     │
│  HKDF-SHA256(PRF output, fixed salt, info) ──► nsec         │
│       │                                                     │
│       ▼                                                     │
│  getPublicKey(nsec) ──► pubkey                              │
│       │                                                     │
│       ▼                                                     │
│  Done. Optionally publish kind:30080 marker event.          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    PASSSEED LOGIN                            │
│                                                             │
│  Step 1: Discovery (no PRF, allowCredentials: [])           │
│  Browser shows passkey picker, user taps one                │
│       │                                                     │
│       ├── userHandle ──► K2 marker (not pubkey)             │
│       └── rawId      ──► credential ID                      │
│                                                             │
│  Step 2: Targeted assertion (allowCredentials: [credId])    │
│       └── PRF output  ──► 32 bytes                          │
│                                                             │
│  HKDF-SHA256(PRF output, fixed salt, info) ──► nsec         │
│       │                                                     │
│       ▼                                                     │
│  getPublicKey(nsec) ──► pubkey                              │
│       │                                                     │
│       ▼                                                     │
│  Done. No relay fetch, no decryption.                       │
└─────────────────────────────────────────────────────────────┘
```

## Specification

### Constants

```
PASSSEED_VERSION     = 1
PASSSEED_PRF_SALT    = UTF-8("keytr-seed-v1")
PASSSEED_HKDF_SALT   = UTF-8("passseed-v1")       // fixed, not random
PASSSEED_HKDF_INFO   = "keytr passseed v1"
PASSSEED_EVENT_KIND  = 30080
PASSSEED_USER_ID     = SHA-256("keytr-passseed-v1")[0:32]
```

NIP-K2 uses a **different PRF salt** (`"keytr-seed-v1"`) than NIP-K1 (`"keytr-v1"`). This ensures the two protocols produce independent PRF outputs even when sharing the same passkey credential, and prevents accidental cross-protocol use.

### User Handle Format

Unlike NIP-K1 — which stores the pubkey in `user.id` for discoverable login — NIP-K2 cannot know the pubkey at registration time (chicken-and-egg: the pubkey is derived from PRF output, which is only available after registration).

NIP-K2 credentials use a **fixed marker** as `user.id`:

```
user.id = SHA-256("keytr-passseed-v1")[0:32]    // 32 bytes, fixed for all K2 credentials
```

During discoverable authentication, the client checks the returned `userHandle`:

- If it matches `PASSSEED_USER_ID` → **K2 flow**: derive nsec from PRF
- If it is a 32-byte value that does NOT match → **K1 flow**: treat as pubkey, fetch relay events

This allows K1 and K2 credentials to coexist under the same rpId. The passkey picker shows both; the client routes to the correct flow based on the marker.

### PRF Extension

NIP-K2 uses the same WebAuthn PRF extension as NIP-K1, but with a **different salt**:

```
PRF_SALT = UTF-8("keytr-seed-v1")    // as ArrayBuffer
```

The salt is fixed by specification — it MUST NOT vary per user or per ceremony. The PRF output is deterministic: the same credential with the same salt always produces the same 32-byte output, on any device that has the synced passkey.

**Browser support**: Chrome 116+, Safari 18+, Edge 116+, Firefox 122+.

### Key Derivation

The nsec is derived deterministically from the PRF output:

```
NSEC = HKDF-SHA256(
  ikm    = PRF_OUTPUT,                  // 32 bytes from authenticator
  salt   = PASSSEED_HKDF_SALT,          // fixed: UTF-8("passseed-v1")
  info   = UTF-8(PASSSEED_HKDF_INFO),   // "keytr passseed v1"
  length = 32                            // 32-byte Nostr private key
)
```

Key differences from NIP-K1 key derivation:

| | NIP-K1 | NIP-K2 |
|---|---|---|
| HKDF salt | Random 32 bytes (unique per encryption) | Fixed string `"passseed-v1"` |
| HKDF info | `"keytr nsec encryption v1"` | `"keytr passseed v1"` |
| Output purpose | AES-256 encryption key | Nostr private key (nsec) directly |
| Determinism | Different key each encryption (random salt) | Same nsec every time (fixed salt) |

The HKDF salt is fixed because determinism is the entire point — the same passkey must always derive the same nsec. The entropy comes from the PRF output, which is already 32 bytes of high-quality randomness bound to the authenticator's internal HMAC secret.

### Registration (Setup)

1. Compute `user.id`:

```javascript
const marker = new Uint8Array(
  await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode('keytr-passseed-v1')
  )
).slice(0, 32)
```

2. Register a WebAuthn passkey:

```javascript
{
  challenge: randomBytes(32),
  rp: {
    name: "Relying Party Name",
    id: rpId                              // e.g., "keytr.org"
  },
  user: {
    id: marker,                           // fixed K2 marker, NOT pubkey
    name: userIdentifier,                 // e.g., "new-user@keytr.org"
    displayName: userDisplayName
  },
  pubKeyCredParams: [
    { type: "public-key", alg: -7 },     // ES256
    { type: "public-key", alg: -257 }    // RS256
  ],
  authenticatorSelection: {
    userVerification: "required",
    residentKey: "required",
    requireResidentKey: true
  },
  attestation: "none",
  extensions: {
    prf: {
      eval: { first: PASSSEED_PRF_SALT } // UTF-8("keytr-seed-v1")
    }
  }
}
```

3. Extract the 32-byte PRF output from `prf.results.first`. If not available during registration (e.g., YubiKey), perform a follow-up assertion against the new credential to obtain it.
4. Derive the nsec:

```javascript
nsec = HKDF-SHA256(prfOutput, PASSSEED_HKDF_SALT, PASSSEED_HKDF_INFO, 32)
```

5. Derive the public key from the nsec.
6. Optionally publish a kind:30080 marker event (see [Marker Event](#marker-event-format)).
7. Zero the PRF output from memory.

### Authentication (Discoverable Login)

1. Call `navigator.credentials.get()`:

```javascript
{
  challenge: randomBytes(32),
  rpId: rpId,                             // e.g., "keytr.org"
  allowCredentials: [],                   // discoverable — browser shows picker
  userVerification: "required",
  extensions: {
    prf: {
      eval: { first: PASSSEED_PRF_SALT } // UTF-8("keytr-seed-v1")
    }
  }
}
```

2. Check the returned `userHandle`:
   - If `userHandle === PASSSEED_USER_ID` → this is a K2 credential, continue below.
   - Otherwise → this is likely a K1 credential, use NIP-K1 flow instead.
3. Extract the 32-byte PRF output from `prf.results.first`.
4. Derive the nsec:

```javascript
nsec = HKDF-SHA256(prfOutput, PASSSEED_HKDF_SALT, PASSSEED_HKDF_INFO, 32)
```

5. Derive the public key from the nsec.
6. Return `{ nsecBytes, pubkey }`. No relay fetch or decryption needed.
7. Zero the PRF output from memory.

### Dual-Protocol Discoverable Login

When a client supports both NIP-K1 and NIP-K2, discoverable authentication uses the same two-step flow as NIP-K1 (required for Safari iOS 18+ compatibility):

```
Step 1: navigator.credentials.get({ allowCredentials: [] })  // no PRF
       │
       ▼
  Check userHandle
       │
       ├── matches PASSSEED_USER_ID ────► K2 path
       │
       └── 32 bytes, not marker ────────► K1 path
       │
Step 2: navigator.credentials.get({ allowCredentials: [credId], prf: ... })
       │
       ├── K2: derive nsec from PRF output
       │
       └── K1: pubkey → fetch relay → decrypt with PRF output
```

Clients SHOULD support both flows transparently. The user selects a passkey from the browser picker; the client routes to the correct protocol based on `userHandle`, then obtains PRF output via a targeted follow-up assertion.

### Marker Event Format

The marker event is **optional**. Its purpose is to signal to other clients that a given pubkey was created via passseed and to provide authentication hints. It contains **no secret material**.

Kind `30080` is a parameterized replaceable event, keyed by credential ID.

```json
{
  "kind": 30080,
  "pubkey": "<derived hex public key>",
  "content": "",
  "tags": [
    ["d", "<credential-id-base64url>"],
    ["rp", "<relying-party-id>"],
    ["method", "passseed"],
    ["v", "1"],
    ["transports", "internal", "hybrid", "..."],
    ["client", "<client-name>"]
  ],
  "created_at": <unix-timestamp>,
  "id": "...",
  "sig": "..."
}
```

### Marker Event Tag Definitions

| Tag | Required | Description |
|-----|----------|-------------|
| `d` | Yes | Base64url-encoded WebAuthn credential ID. Parameterized replaceable key. |
| `rp` | Yes | WebAuthn Relying Party ID (domain). Tells clients which rpId to use for authentication. |
| `method` | Yes | MUST be `"passseed"`. Distinguishes K2 markers from other event kinds. |
| `v` | Yes | Passseed protocol version. Currently `"1"`. |
| `transports` | No | Authenticator transports (e.g., `internal`, `hybrid`, `usb`). Helps optimize UX. |
| `client` | No | Name of the client that created this event. Informational. |

The marker event is signed with the derived nsec. This proves the publisher controls the passkey that produced the identity.

### When to Publish a Marker Event

- **Publish** if the user intends to use the identity across multiple clients or wants other clients to know the login method.
- **Skip** if the identity is ephemeral, disposable, or the user prefers zero relay footprint.

Clients that encounter a kind:30080 event for a pubkey know they can offer passseed login for that identity.

## Cross-Client Compatibility

### Gateway Model

NIP-K2 uses the same federated gateway model as NIP-K1 (see NIP-K1 § Cross-Client Compatibility). A passkey registered with `rpId: "keytr.org"` on any authorized origin produces the same PRF output on every authorized origin.

### rpId Binding

**A passseed identity is bound to a single rpId.** Different rpIds produce different PRF outputs, which derive different nsecs, which produce different pubkeys. There is no way to share a passseed identity across rpIds without the Related Origin Requests mechanism.

This is a fundamental difference from NIP-K1, where the same nsec can be encrypted under multiple rpIds. With passseeds:

| Scenario | Result |
|---|---|
| Same credential, same rpId, any authorized origin | Same nsec (correct) |
| Same credential, different rpId | Different nsec (different identity) |
| Different credential, same rpId | Different nsec (different identity) |

For portability, users SHOULD register their passseed against a well-known gateway (e.g., `keytr.org`) rather than a standalone client domain, so any client authorized by that gateway can derive the same identity.

### Multi-Gateway Considerations

If a user registers passseeds on multiple gateways, they get **separate identities** (one per rpId). This can be intentional (compartmentalization) but may surprise users expecting a single identity.

Clients SHOULD warn users when registering a passseed on a new rpId that it will create a new, separate identity.

## Security Model

### PRF as Sole Key Material

The entire identity derives from the PRF output. The security of a passseed identity reduces to the security of the authenticator's PRF implementation:

- The PRF secret is internal to the authenticator hardware. It never leaves the secure element.
- The PRF output is deterministic given the same credential + salt + rpId.
- An attacker who compromises the relay (or the marker event) learns nothing about the nsec — the marker contains no encrypted material, and the pubkey is already public.

### No Ciphertext Exposure

Unlike NIP-K1, there is no encrypted blob for an attacker to target. The relay stores only the marker event (pubkey, rpId, transports) — all public information. There is no offline attack surface.

### Origin Binding

Same as NIP-K1: the PRF output is bound to the rpId. A phishing site on a different domain produces a different PRF output, deriving a different (useless) nsec.

### User Verification

Every ceremony requires `userVerification: "required"`. Physical access to the device is not sufficient without biometric or PIN.

### Credential Loss

**If all passkeys holding the credential are deleted, the identity is permanently lost.** There is no encrypted backup on relays to fall back to (unlike NIP-K1).

Mitigations:

- **NIP-K1 escape hatch**: After deriving the nsec via passseed, encrypt it with NIP-K1 and publish to relays. This gives the user a relay-backed backup while keeping the passseed as the primary login method.
- **NIP-49 backup**: Export the derived nsec as a password-encrypted backup.
- **Multiple synced devices**: Passkeys sync via iCloud Keychain, Google Password Manager, etc. Deleting from one device does not delete from all (unless the user explicitly removes the credential from the sync provider).

Clients MUST warn users about credential loss and SHOULD encourage at least one backup method.

### Memory Hygiene

Implementations SHOULD zero the PRF output and derived nsec from memory after use. In JavaScript, overwrite `Uint8Array` contents with zeros in a `finally` block.

### Determinism Risks

Because the nsec is deterministic, there is no "re-roll" without creating a new credential. If a user suspects their passkey is compromised, they must:

1. Create a new passkey (new credential → new PRF output → new nsec → new pubkey)
2. Migrate their social graph to the new identity
3. Delete the compromised credential

This is a harder recovery path than NIP-K1, where re-encryption with a new passkey preserves the same nsec/pubkey. Clients SHOULD document this tradeoff.

## Compatibility

### Authenticator Requirements

NIP-K2 has the same authenticator requirements as NIP-K1:

| Requirement | Detail |
|---|---|
| PRF extension | Required. Authenticator must support `hmac-secret` / PRF. |
| Discoverable credentials | Required. `residentKey: "required"`. |
| User verification | Required. Biometric or PIN. |
| Syncing | Recommended. Platform authenticators sync passkeys across devices. |

All authenticators that support NIP-K1 support NIP-K2. The compatibility matrix is identical:

| Authenticator | PRF | Discoverable | Syncs | K1 | K2 |
|---|---|---|---|---|---|
| iCloud Keychain | Yes | Yes | Yes | Yes | Yes |
| Google Password Manager | Yes | Yes | Yes | Yes | Yes |
| Windows Hello | Yes | Yes | No | Yes | Yes |
| YubiKey 5 | Yes* | Yes (25 slots) | No | Yes* | Yes* |
| Bitwarden (extension) | No | Yes | Yes | No | No |
| 1Password (extension) | No | Yes | Yes | No | No |
| Dashlane (extension) | No | Yes | Yes | No | No |

\* YubiKey returns PRF only during authentication, not registration. Implementations must perform a follow-up assertion to obtain the initial PRF output.

### Password Manager Extension Conflict

The same password manager extension conflict described in NIP-K1 applies to NIP-K2. Extensions that intercept WebAuthn calls without supporting PRF or Related Origin Requests will block passseed ceremonies. See NIP-K1 § Known Issues for workarounds.

## Multiple Passkeys

Unlike NIP-K1 — where multiple passkeys each encrypt the same nsec independently — NIP-K2 passkeys each derive a **different nsec** (different credential → different PRF secret → different output).

Registering a second passkey as a "backup" creates a second identity with a different pubkey. This is generally NOT what users want.

For backup with the same identity, use:

1. **NIP-K1 as backup**: Encrypt the passseed-derived nsec with the backup passkey using NIP-K1. The backup passkey stores the encrypted blob on relays; the primary passkey derives the nsec directly.
2. **Device sync**: Rely on passkey sync (iCloud, Google) to distribute the same credential across devices. Same credential = same PRF = same nsec.
3. **NIP-49 export**: Password-encrypt the derived nsec for offline storage.

## Constants

```
PASSSEED_VERSION     = 1
PASSSEED_EVENT_KIND  = 30080
PASSSEED_PRF_SALT    = UTF-8("keytr-seed-v1")
PASSSEED_HKDF_SALT   = UTF-8("passseed-v1")
PASSSEED_HKDF_INFO   = "keytr passseed v1"
PASSSEED_USER_ID     = SHA-256("keytr-passseed-v1")[0:32]
```

## Relation to Other NIPs

| NIP | Relation |
|-----|----------|
| NIP-K1 | Complementary: K1 encrypts existing nsecs; K2 derives new ones. K1 serves as a backup mechanism for K2 identities. |
| NIP-01 | Standard event structure used for kind:30080 marker events |
| NIP-49 | Can be used as a backup method for the derived nsec |
| NIP-07 | Browser extension signers can integrate K2 for key derivation on login |
| NIP-46 | Alternative approach: NIP-46 delegates signing remotely; K2 derives keys locally |
