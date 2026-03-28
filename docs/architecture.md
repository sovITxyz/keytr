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

1. Convert the hex pubkey to bytes and set as `user.id` (32 bytes — enables discoverable login)
2. Generate random challenge
3. Build `CredentialCreationOptions`:
   - `rpId`: defaults to `"keytr.org"` (or custom domain)
   - Algorithms: ES256 (-7), RS256 (-257)
   - `authenticatorSelection`: resident key required, user verification required
   - `extensions`: PRF with salt `"keytr-v1"`
4. Call `navigator.credentials.create()`
5. Extract the 32-byte PRF output from `prf.results.first`. If not available (e.g., YubiKey), perform a follow-up assertion against the new credential to obtain it.
6. Extract credential ID (raw bytes + base64url), rpId, transports
7. Return `{ credential: KeytrCredential, prfOutput: Uint8Array }`

Source: `src/webauthn/register.ts`

### Authentication (Known Credential)

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

### Authentication (Discoverable)

`discoverPasskey(options?)` does:

1. Build `CredentialRequestOptions`:
   - `rpId`: defaults to `"keytr.org"`
   - Random challenge
   - `allowCredentials: []` — empty, so the browser shows all resident keys for this rpId
   - `extensions`: PRF with salt `"keytr-v1"`
2. Call `navigator.credentials.get()` — browser shows passkey picker, user selects one
3. Extract pubkey from `response.userHandle` (the 32-byte public key set during registration)
4. Extract 32-byte PRF output
5. Extract credential ID from `rawId`
6. Return `{ pubkey, prfOutput, credentialId }`

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
3. `nsecToHexPubkey(nsec)` → hex pubkey (passed to registerPasskey as `user.id`)
4. `registerPasskey({ ...options, pubkey })` → credential + PRF output
5. `encryptNsec({ nsecBytes, prfOutput, credentialId })` → base64 blob
6. Zero out PRF output (in `finally` block)
7. `buildKeytrEvent({ credential, encryptedBlob })` → unsigned event template
8. Return everything

The caller is responsible for: signing the event with the nsec, publishing it to relays, and zeroing `nsecBytes` after use.

Source: `src/index.ts`

### Backup Gateway Registration

```typescript
const bundle = await addBackupGateway(nsecBytes, {
  rpId: 'nostkey.org',
  rpName: 'nostkey.org',
  userName: npub,
  userDisplayName: 'Nostr User',
  clientName: 'my-app',
})
// bundle: { credential, encryptedBlob, eventTemplate }
```

Internally:

1. `registerPasskey(options)` → credential + PRF output (triggers biometric)
2. `encryptNsec({ nsecBytes, prfOutput, credentialId })` → base64 blob
3. Zero out PRF output (in `finally` block)
4. `buildKeytrEvent({ credential, encryptedBlob })` → unsigned event template
5. Return the bundle

This is a separate action from setup — the user opts in when they want resilience against a gateway going down.

Source: `src/index.ts`

### Discoverable Login (No Prior State)

```typescript
const { nsecBytes, npub, pubkey } = await discoverAndLogin(
  ['wss://relay.damus.io'],
  { rpId: 'keytr.org' }
)
```

One call, no npub input needed:

1. `discoverPasskey({ rpId })` → browser shows passkey picker → returns pubkey, PRF output, credential ID
2. `fetchKeytrEvents(pubkey, relays)` → fetch kind:30079 events for the recovered pubkey
3. Match the event whose `d` tag equals `base64url(credentialId)`
4. `decryptNsec({ encryptedBlob, prfOutput, credentialId })` → 32-byte nsec
5. Zero out PRF output (in `finally` block)
6. Return `{ nsecBytes, npub, pubkey }`

If no matching event is found, throws `KeytrError` (the passkey may have been registered before discoverable login was enabled).

Source: `src/index.ts`

### Login with Known Pubkey

```typescript
const events = await fetchKeytrEvents(pubkey, relayUrls)
const { nsecBytes, npub } = await loginWithKeytr(events)
```

Accepts an **array** of kind:30079 events. Tries each event in order until a matching passkey succeeds:

1. For each event:
   a. `parseKeytrEvent(event)` → extract credential ID, rpId, blob
   b. `authenticatePasskey({ credentialId, rpId, transports })` → PRF output (triggers biometric)
   c. If the authenticator rejects (no matching credential), skip to the next event
   d. `decryptNsec({ encryptedBlob, prfOutput, credentialId })` → 32-byte nsec
   e. Zero out PRF output (in `finally` block)
   f. Return `{ nsecBytes, npub }`
2. If no event succeeds, throw `WebAuthnError`

This flow is useful when the client already knows the pubkey (e.g., from localStorage or a URL parameter).

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

### Cross-Gateway Trust

The two official gateways — `keytr.org` (Cloudflare Pages) and `nostkey.org` (GitHub Pages) — trust each other via bidirectional Related Origin Requests. Each gateway's `/.well-known/webauthn` lists the other as an authorized origin:

```json
// https://keytr.org/.well-known/webauthn
{
  "origins": [
    "https://keytr.org",
    "https://nostkey.org",
    "https://bies.sovit.xyz",
    "https://gitvid.sovit.xyz",
    "https://nostrbook.net"
  ]
}
```

```json
// https://nostkey.org/.well-known/webauthn
{
  "origins": [
    "https://nostkey.org",
    "https://keytr.org",
    "https://bies.sovit.xyz",
    "https://gitvid.sovit.xyz",
    "https://nostrbook.net"
  ]
}
```

This means:

- A passkey registered with `rpId: "keytr.org"` can be used from `nostkey.org` (and vice versa)
- A passkey registered with either rpId can be used from any authorized client origin (bies, gitvid, nostrbook)
- The browser fetches the `.well-known/webauthn` file from the rpId domain and verifies the requesting origin is listed before allowing the WebAuthn ceremony

In practice, a user on `nostkey.org` authenticating with a passkey bound to `keytr.org` works like this:

1. Client calls `navigator.credentials.get({ publicKey: { rpId: "keytr.org" } })` from `nostkey.org`
2. Browser fetches `https://keytr.org/.well-known/webauthn`
3. Browser confirms `https://nostkey.org` is in the origins list
4. Authenticator runs the ceremony using `keytr.org` as the rpId — returns the same credential and user handle as if the user were on `keytr.org` directly

**Browser support**: Chrome 128+ (desktop and Android), Safari 18+ (iOS 18+, macOS Sequoia+).

### Adding a New Client Origin

To authorize a new Nostr client to use a gateway's passkeys:

1. Add the client's origin to the gateway's `/.well-known/webauthn` origins array
2. Deploy the updated file
3. The client can now call WebAuthn with the gateway's rpId

For the official gateways, submit a PR to [sovITxyz/keytr.org](https://github.com/sovITxyz/keytr.org) or [nostkey/nostkey.org](https://github.com/nostkey/nostkey.org).

### Standalone Mode

A client can skip gateways entirely and use its own domain as the rpId. Only that domain can decrypt. The `rp` tag in the event tells other clients which origin to visit if they want to attempt decryption.

### Recommended Strategy

1. Register against the primary gateway (`keytr.org`) during setup — **one biometric prompt**
2. Optionally register a backup gateway (`nostkey.org`) via `addBackupGateway()` — separate action, separate prompt
3. Support decryption of events under any rpId the client is authorized for

Related Origin Requests mean a single passkey on `keytr.org` already works from `nostkey.org` for day-to-day use. The backup gateway is for resilience — if `keytr.org` goes down, the browser can't fetch its `.well-known/webauthn`, so a separate credential on `nostkey.org` keeps the user's key accessible.

---

## Native & P2P Clients (No DNS)

### The Problem

The WebAuthn browser API requires HTTPS origins, DNS-resolvable rpIds, and `navigator.credentials`. Native runtimes like **Pear** (Holepunch's P2P application runtime) have none of these — apps are identified by public keys, distributed via Hypercore, and have no DNS or TLS.

### The Solution: CTAP2 Direct

Under the hood, browsers talk to authenticators via **CTAP2** (Client to Authenticator Protocol). The browser adds origin/DNS verification on top, but the authenticator itself doesn't enforce it. The rpId is just a string the authenticator hashes for credential scoping.

A native app can bypass the browser layer entirely:

```
Browser client:  navigator.credentials.get() → PRF extension  → prfOutput
Native app:      libfido2 CTAP2 call         → hmac-secret    → same output
                                                                    │
                                              decrypt kind:30079 event
```

The authenticator doesn't know or care whether `"keytr.org"` resolves in DNS. It matches the rpId hash against stored credentials and returns the same HMAC output regardless of how the request arrived.

### What a Native Client Needs

1. **CTAP2 bindings** — `libfido2` (Yubico's C library) via N-API addon is the most proven path. For Pear/Bare runtime, this would be a native addon.
2. **Same rpId string** — use `"keytr.org"` (or whichever gateway) as a plain string parameter to the CTAP2 call.
3. **`hmac-secret` extension** — the CTAP2 wire-level equivalent of WebAuthn's PRF extension. Use the same salt (`"keytr-v1"`) to get byte-identical output.
4. **Everything else is the same** — the encrypted blob format, kind:30079 event structure, HKDF derivation, and AES-GCM decryption are all platform-agnostic. Only the authenticator communication layer differs.

### nostr-swarm Integration

[nostr-swarm](https://github.com/sovITxyz/nostr-swarm) is a fully P2P Nostr relay built on the Holepunch stack (Hyperswarm + Autobase + Hyperbee). It provides two access modes:

- **WebSocket**: Traditional Nostr clients connect via NIP-01 WebSocket
- **Hyperswarm direct**: Pear apps join the swarm topic and replicate the Autobase directly — no HTTP, no DNS, no WebSocket overhead

For keytr, this means a Pear app can:

1. **Fetch kind:30079 events** directly from the Hyperswarm-replicated event store — no relay URLs, no DNS lookups
2. **Authenticate via CTAP2** using `libfido2` with `rpId: "keytr.org"` + `hmac-secret` salt `"keytr-v1"`
3. **Decrypt the nsec** using the same blob format and crypto as browser clients
4. **Publish new events** (backup passkey registrations, re-encryptions) back to the swarm

The entire flow is DNS-free and server-free. Peers discover each other via DHT (`sha256("nostr-swarm:" + topic)`), and the Autobase ensures all peers converge on the same event set.

```
Pear app
  │
  ├── nostr-swarm (Hyperswarm) ── fetch/publish kind:30079 events
  │
  └── libfido2 (CTAP2) ── hmac-secret with rpId:"keytr.org"
        │
        └── decrypt nsec ── same blob format as browser clients
```

### Browser vs Native Comparison

| Concern | Browser (WebAuthn) | Native (CTAP2) |
|---------|--------------------|----------------|
| Authenticator API | `navigator.credentials` | `libfido2` / platform CTAP2 |
| PRF mechanism | `prf` extension | `hmac-secret` extension |
| rpId validation | Browser enforces DNS + origin | App passes string directly |
| Related Origins | `.well-known/webauthn` fetch | Not needed (no origin check) |
| Relay access | WebSocket to relay URLs | Hyperswarm direct or WebSocket |
| Event format | kind:30079 | kind:30079 (identical) |
| Crypto | Same (HKDF + AES-256-GCM) | Same |

### Security Considerations for Native Clients

Without the browser's origin enforcement, native clients take on responsibility for:

- **rpId integrity** — the app must use the correct rpId string. A malicious app could use any rpId to trigger credential lookup, but without the correct PRF salt and credential ID, decryption will fail (AAD mismatch).
- **User consent** — the authenticator still requires biometric/PIN for every operation. The user always approves.
- **Code trust** — users must trust the native app's code (same as any native key management tool). Pear apps are content-addressed by public key, providing a verifiable identity.

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

## Known Issues

### Password Manager Extensions Intercepting WebAuthn

Browser extensions from password managers — **Bitwarden**, **1Password**, **Dashlane**, and others — can intercept `navigator.credentials.create()` and `navigator.credentials.get()` calls. These extensions register their own WebAuthn handler to offer passkey management through the password manager rather than the browser's native passkey UI.

The problem: most password manager extensions **do not support Related Origin Requests**. When keytr calls `navigator.credentials.get()` with `rpId: "keytr.org"` from an authorized client origin like `bies.sovit.xyz`, the browser would normally:

1. Fetch `https://keytr.org/.well-known/webauthn`
2. Verify `https://bies.sovit.xyz` is in the origins list
3. Allow the ceremony to proceed

But if a password manager extension intercepts the call first, it applies its own origin validation — which typically requires an exact match between the requesting origin and the rpId. Since `bies.sovit.xyz !== keytr.org`, the extension rejects the request with an error like:

- `SecurityError: The relying party ID is not a registrable domain suffix of, nor equal to the current domain.`
- `NotAllowedError: The operation either timed out or was not allowed.`

This affects **all cross-origin flows** — any client using a gateway rpId different from its own domain will fail when these extensions are active.

#### Workarounds for Users

- **Disable the password manager's WebAuthn/passkey integration** in the extension settings. The browser's native passkey support will handle the ceremony correctly.
  - Bitwarden: Settings → Options → disable "Enable passkey management"
  - 1Password: Settings → Autofill and save → disable "Passkeys"
  - Dashlane: Settings → Autofill → disable "Passkey support"
- **Use the extension's allow-list** if available to exclude keytr gateway domains from interception.
- **Use a browser profile without password manager extensions** for Nostr clients that rely on keytr passkeys.

#### Recommendations for Client Developers

When a `SecurityError` or `NotAllowedError` occurs during a WebAuthn ceremony where the rpId differs from the current origin, clients should detect this condition and display a targeted hint:

```
Passkey authentication failed. If you have a password manager extension
(Bitwarden, 1Password, Dashlane, etc.) installed, it may be intercepting
WebAuthn requests without supporting cross-origin passkeys.

Try disabling passkey/WebAuthn support in your password manager extension
settings and retry.
```

This detection can be implemented by checking:
1. The error is a `SecurityError` or `NotAllowedError`
2. The rpId used does not match `window.location.hostname`
3. The rpId is a known keytr gateway (e.g., `keytr.org`, `nostkey.org`)

If all three conditions are true, the error is likely caused by extension interception rather than a genuine security violation or user cancellation.

#### Long-Term Outlook

Password manager vendors are gradually adding Related Origin Request support. As adoption grows, this issue will diminish. In the meantime, client-side error detection and user guidance are the best mitigation.

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
KEYTR_GATEWAYS   = ["keytr.org", "nostkey.org"]
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
RegisterOptions, AuthenticateOptions, DiscoverOptions, DiscoverResult,
KeytrBundle
```

### High-Level

```typescript
setupKeytr(options)              // Full registration flow (1 passkey prompt)
addBackupGateway(nsec, options)  // Register backup on another gateway
discoverAndLogin(relays, opts?)  // Discoverable login — no npub needed
loginWithKeytr(events)           // Try each event until a passkey matches
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
registerPasskey(options)           // Create passkey + get PRF (pubkey stored as user.id)
authenticatePasskey(options)       // Assert known passkey + get PRF
discoverPasskey(options?)          // Discoverable auth — returns pubkey + PRF + credentialId
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
