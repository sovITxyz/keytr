# keytr

Passkey login for Nostr. Encrypt your nsec with a WebAuthn passkey, publish to relays, decrypt on any device. Implements [NIP-K1](nip/nip-k1.md).

## How it works

Register a passkey, encrypt your nsec with the passkey's PRF output, publish the ciphertext to Nostr relays. On any device with the synced passkey, tap to decrypt — no npub input needed, no localStorage, no manual key copying.

```
Passkey PRF → HKDF-SHA256 → AES-256-GCM → kind:31777 event → relay
```

Cross-client login works via a [federated gateway model](docs/architecture.md#federated-gateway-model) — any domain can authorize a set of Nostr clients to share passkey access using WebAuthn [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins). The two official gateways (`keytr.org` on Cloudflare, `nostkey.org` on Hostinger) trust each other bidirectionally, so a passkey registered under either rpId works on both sites and all authorized client origins.

## Documentation

- [Architecture & System Design](docs/architecture.md) — detailed walkthrough of every layer: crypto, WebAuthn, Nostr integration, federated gateways, security model
- [Integration Guide](docs/integration-guide.md) — how to wire keytr into a Nostr client's auth flow, session restore, and credential management
- [Roadmap](docs/roadmap.md) — current state and future direction (NIP-K2 passseeds)
- [NIP-K1 Specification](nip/nip-k1.md) — the protocol spec

## Install

```bash
npm install @sovit.xyz/keytr
```

## Quick start

### Setup (new user)

```typescript
import { setupKeytr, publishKeytrEvent } from '@sovit.xyz/keytr'
import { finalizeEvent } from 'nostr-tools/pure'

const { credential, encryptedBlob, eventTemplate, nsecBytes, npub } = await setupKeytr({
  userName: 'alice',
  userDisplayName: 'Alice',
})

// Sign and publish
const signedEvent = finalizeEvent(eventTemplate, nsecBytes)
await publishKeytrEvent(signedEvent, ['wss://relay.damus.io'])
```

### Login (discoverable — no npub needed)

```typescript
import { discoverAndLogin } from '@sovit.xyz/keytr'

// Browser shows available passkeys, user picks one, nsec is recovered
const { nsecBytes, npub, pubkey } = await discoverAndLogin(
  ['wss://relay.damus.io'],
  { rpId: 'keytr.org' }
)
```

### Login (known pubkey)

```typescript
import { loginWithKeytr, fetchKeytrEvents } from '@sovit.xyz/keytr'

const events = await fetchKeytrEvents(pubkey, ['wss://relay.damus.io'])
const { nsecBytes, npub } = await loginWithKeytr(events)
```

## Compatibility

keytr requires the WebAuthn [PRF extension](https://w3c.github.io/webauthn/#prf-extension) and [discoverable credentials](https://w3c.github.io/webauthn/#client-side-discoverable-credential). PRF is the primary compatibility gate.

### Browsers

| Browser | Min Version | PRF | Discoverable Login | Notes |
|---------|-------------|-----|--------------------|-------|
| Chrome (Desktop) | 116+ | Yes | Yes | |
| Chrome (Android) | 116+ | Yes | Yes | Requires Google Password Manager or PRF-capable security key |
| Edge | 116+ | Yes | Yes | Chromium-based, same support as Chrome |
| Safari | 18+ | Yes | Two-step | iOS/iPadOS: PRF unavailable during discovery — keytr handles this automatically |
| Firefox | 122+ | Yes | Yes | |
| Firefox Android | — | No | — | PRF not supported |

### Authenticators

| Authenticator | PRF | Notes |
|---------------|-----|-------|
| iCloud Keychain | Yes | macOS 15+ / iOS 18+ |
| Google Password Manager | Yes | Android 14+ / Chrome 116+ |
| Windows Hello | Yes | Windows 10 22H2+ / Chrome 116+ |
| YubiKey 5 (firmware 5.7+) | Yes | Via `hmac-secret` → PRF bridge |
| YubiKey 5 (firmware < 5.7) | No | No PRF / hmac-secret support |
| Older security keys | No | Require PRF-capable firmware |

### Federated gateways

Cross-client login via [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) requires additional browser support:

| Browser | Related Origins | Min Version |
|---------|-----------------|-------------|
| Chrome | Yes | 128+ |
| Edge | Yes | 128+ |
| Safari | Yes | 18+ |
| Firefox | No | Not yet supported |

Use `checkPrfSupport()` at runtime to detect whether the current browser + authenticator combination supports PRF before showing passkey UI.

## Security properties

- **Hardware-bound** — PRF output requires physical authenticator + biometric/PIN
- **Origin-bound** — phishing sites on different domains get useless PRF output
- **AAD-bound** — ciphertext tied to specific credential ID and version
- **No server trust** — relay is a dumb store, encryption is end-to-end
- **Memory hygiene** — PRF output and derived keys zeroed after use

## License

AGPL-3.0-or-later
