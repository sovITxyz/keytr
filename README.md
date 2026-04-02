# keytr

Passkey login for Nostr. Encrypt your nsec with a WebAuthn passkey, publish to relays, decrypt on any device. Implements [NIP-K1](nip/nip-k1.md).

## How it works

Register a passkey, encrypt your nsec, publish the ciphertext to Nostr relays. On any device with the synced passkey, tap to decrypt — no npub input needed, no localStorage, no manual key copying.

keytr supports two encryption modes:

- **PRF mode** — the passkey's PRF extension produces a deterministic secret for key derivation. Strongest security (hardware-bound), requires PRF-capable authenticators.
- **KiH mode** (Key-in-Handle) — a random 256-bit encryption key is stored in the passkey's `user.id` field. Works with **all** authenticators, including those without PRF support (e.g., Firefox Android, older security keys). Always 1 biometric prompt.

Both modes use the same crypto pipeline: HKDF-SHA256 + AES-256-GCM. The unified `setup()` API tries PRF first and falls back to KiH automatically.

```
PRF mode:  Passkey PRF → HKDF-SHA256 → AES-256-GCM → kind:31777 (v=1) → relay
KiH mode:  Random key in user.id → HKDF-SHA256 → AES-256-GCM → kind:31777 (v=3) → relay
```

Cross-client login works via a [federated gateway model](docs/architecture.md#federated-gateway-model) — any domain can authorize a set of Nostr clients to share passkey access using WebAuthn [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins). The two official gateways (`keytr.org` on Cloudflare, `nostkey.org` on Hostinger) trust each other bidirectionally, so a passkey registered under either rpId works on both sites and all authorized client origins.

## Documentation

- [Architecture & System Design](docs/architecture.md) — detailed walkthrough of every layer: crypto, WebAuthn, Nostr integration, federated gateways, security model
- [Integration Guide](docs/integration-guide.md) — how to wire keytr into a Nostr client's auth flow, session restore, and credential management
- [Roadmap](docs/roadmap.md) — current state and future direction
- [NIP-K1 Specification](nip/nip-k1.md) — the protocol spec

## Install

```bash
npm install @sovit.xyz/keytr
```

## Quick start

### Setup (new user)

```typescript
import { setup, publishKeytrEvent } from '@sovit.xyz/keytr'
import { finalizeEvent } from 'nostr-tools/pure'

// Tries PRF first, falls back to KiH if authenticator doesn't support PRF
const { credential, encryptedBlob, eventTemplate, nsecBytes, npub, mode } = await setup({
  userName: 'alice',
  userDisplayName: 'Alice',
})

console.log(`Registered in ${mode} mode`) // 'prf' or 'kih'

// Sign and publish
const signedEvent = finalizeEvent(eventTemplate, nsecBytes)
await publishKeytrEvent(signedEvent, ['wss://relay.damus.io'])
```

### Login (discoverable — no npub needed)

```typescript
import { discover } from '@sovit.xyz/keytr'

// Browser shows passkeys, user picks one, mode auto-detected from userHandle
const { nsecBytes, npub, pubkey, mode } = await discover(
  ['wss://relay.damus.io'],
  { rpId: 'keytr.org' }
)

console.log(`Logged in via ${mode} mode`) // 'prf' or 'kih'
```

### Login (known pubkey — PRF mode only)

```typescript
import { loginWithKeytr, fetchKeytrEvents } from '@sovit.xyz/keytr'

const events = await fetchKeytrEvents(pubkey, ['wss://relay.damus.io'])
const { nsecBytes, npub } = await loginWithKeytr(events)
```

The previous `setupKeytr()` and `discoverAndLogin()` functions remain available for backward compatibility.

## Module exports

keytr provides four entry points for tree-shaking and selective imports:

| Export | Path | Contents |
|--------|------|----------|
| Main | `@sovit.xyz/keytr` | High-level API + re-exports from all modules |
| Crypto | `@sovit.xyz/keytr/crypto` | `encryptNsec`, `decryptNsec`, `deriveKey`, `serializeBlob`, `deserializeBlob`, `buildAad` |
| WebAuthn | `@sovit.xyz/keytr/webauthn` | `registerPasskey`, `registerKihPasskey`, `authenticatePasskey`, `discoverPasskey`, `unifiedDiscover`, `checkPrfSupport`, `checkCapabilities`, `ensureBrowser`, KiH helpers, Signal API, backup flags |
| Nostr | `@sovit.xyz/keytr/nostr` | Key utilities, event building/parsing, relay operations |

## Compatibility

keytr requires [discoverable credentials](https://w3c.github.io/webauthn/#client-side-discoverable-credential). PRF mode additionally requires the [PRF extension](https://w3c.github.io/webauthn/#prf-extension). KiH mode works without PRF.

### Browsers

| Browser | Min Version | PRF Mode | KiH Mode | Discoverable Login | Notes |
|---------|-------------|----------|----------|--------------------|-------|
| Chrome (Desktop) | 116+ | Yes | Yes | Yes | |
| Chrome (Android) | 116+ | Yes | Yes | Yes | |
| Edge | 116+ | Yes | Yes | Yes | Chromium-based |
| Safari | 18+ | Yes | Yes | Yes | PRF discovery requires two biometric prompts; KiH completes in one |
| Firefox | 122+ | Yes | Yes | Yes | |
| Firefox Android | — | No | Yes | Yes | No PRF support — KiH fallback works |

### Authenticators

| Authenticator | PRF Mode | KiH Mode | Notes |
|---------------|----------|----------|-------|
| iCloud Keychain | Yes | Yes | macOS 15+ / iOS 18+ |
| Google Password Manager | Yes | Yes | Android 14+ / Chrome 116+ |
| Windows Hello | Yes | Yes | Windows 11 25H2+ (Feb 2026 update) |
| YubiKey 5 (firmware 5.7+) | Yes | Yes | PRF via `hmac-secret` bridge |
| YubiKey 5 (firmware < 5.7) | No | Yes | KiH fallback works |
| 1Password | Yes | Yes | PRF supported across platforms |
| Bitwarden | Yes | Yes | PRF supported since 2026.1.1 (Chromium-based browsers) |
| Dashlane | Beta | Yes | PRF in beta (browser extension only); KiH as stable fallback |
| Older security keys | No | Yes | KiH works with any WebAuthn authenticator |

### Federated gateways

Cross-client login via [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) requires additional browser support:

| Browser | Related Origins | Min Version |
|---------|-----------------|-------------|
| Chrome | Yes | 128+ |
| Edge | Yes | 128+ |
| Safari | Yes | 18+ |
| Firefox | No | Positive standards position (March 2026); no implementation timeline |

### Capability detection

Use `checkPrfSupport()` for PRF-only checks, or `checkCapabilities()` for a comprehensive report including PRF, conditional mediation, Related Origins, and Signal API support. The unified `setup()` API tries PRF first and automatically falls back to KiH when PRF is unavailable — no conditional logic needed in calling code.

```typescript
import { checkCapabilities } from '@sovit.xyz/keytr'

const caps = await checkCapabilities()
// caps.prf              — true/false/null (null = unknown, requires credential creation to confirm)
// caps.conditionalMediation — passkey autofill support
// caps.relatedOrigins   — cross-domain passkey use (federated gateways)
// caps.signalApi        — credential lifecycle management
```

Uses `PublicKeyCredential.getClientCapabilities()` (Chrome 132+) when available, falls back to feature detection.

### Conditional UI (passkey autofill)

Pass `mediation: 'conditional'` to `discover()` or `discoverPasskey()` for passkey autofill instead of the modal picker. Requires `<input autocomplete="webauthn">` in the DOM:

```typescript
const { nsecBytes, pubkey, mode } = await discover(relays, {
  mediation: 'conditional',  // passkey suggestions appear in the input field
})
```

### Credential lifecycle (Signal API)

Tell authenticators to clean up revoked or stale passkeys (Chrome 132+). No-ops on unsupported browsers:

```typescript
import { signalUnknownCredential, signalAllAcceptedCredentialIds } from '@sovit.xyz/keytr'

// User deleted their passkey — tell authenticators to remove it
await signalUnknownCredential('keytr.org', credentialId)

// Sync the full set of valid credentials for a user
await signalAllAcceptedCredentialIds('keytr.org', userId, [credId1, credId2])
```

### Backup eligibility

After registration, `KeytrCredential` includes backup flags from `authenticatorData`:

```typescript
const { credential } = await setup({ ... })
if (credential.backupEligible === false) {
  console.warn('This passkey is device-bound and will not sync across devices')
}
```

### SSR safety

All WebAuthn functions throw `WebAuthnError` immediately in non-browser environments (Node.js, SSR). Use `ensureBrowser()` for explicit pre-checks in SSR frameworks:

```typescript
import { ensureBrowser } from '@sovit.xyz/keytr'

try { ensureBrowser() } catch { /* render fallback UI */ }
```

## Security properties

| Property | PRF Mode | KiH Mode |
|----------|----------|----------|
| **Hardware-bound** | Yes — PRF output requires authenticator + biometric | Partially — key stored in passkey credential |
| **Origin-bound** | Yes — different domains get different PRF output | Yes — passkey still bound to rpId |
| **AAD-bound** | `"keytr" \|\| 0x01 \|\| credentialId` | `"keytr" \|\| 0x03 \|\| credentialId` |
| **Cross-mode isolation** | AAD version byte prevents KiH blobs decrypting as PRF | AAD version byte prevents PRF blobs decrypting as KiH |
| **No server trust** | Relay is a dumb store, encryption is end-to-end | Same |
| **Memory hygiene** | Keys zeroed after use | Same |

KiH mode trades PRF's hardware-bound key derivation for universal authenticator compatibility. The encryption key is a random 256-bit value stored in the passkey's `user.id` field — still protected by the passkey's biometric/PIN requirement, but extractable by the authenticator (unlike PRF output, which never leaves the hardware). Now that most major password managers support PRF, KiH primarily serves as an automatic fallback for environments where PRF is unavailable (e.g., Firefox Android, older security keys).

## License

AGPL-3.0-or-later
