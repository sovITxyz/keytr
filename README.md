# keytr

Passkey login for Nostr. Encrypt your nsec with a WebAuthn passkey, publish to relays, decrypt on any device. Implements [NIP-K1](nip/nip-k1.md).

## How it works

Register a passkey, encrypt your nsec with the passkey's PRF output, publish the ciphertext to Nostr relays. On a new device, authenticate with the same synced passkey to decrypt. No server trust, no passwords, no manual key copying.

```
Passkey PRF → HKDF-SHA256 → AES-256-GCM → kind:30079 event → relay
```

Cross-client login works via a [federated gateway model](docs/architecture.md#federated-gateway-model) — any domain can authorize a set of Nostr clients to share passkey access using WebAuthn Related Origin Requests.

## Documentation

- [Architecture & System Design](docs/architecture.md) — detailed walkthrough of every layer: crypto, WebAuthn, Nostr integration, federated gateways, security model
- [NIP-79 Specification](nip/nip-79.md) — the protocol spec

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

### Login (key recovery)

```typescript
import { loginWithKeytr, fetchKeytrEvents } from '@sovit.xyz/keytr'

const events = await fetchKeytrEvents(pubkey, ['wss://relay.damus.io'])
const { nsecBytes, npub } = await loginWithKeytr(events[0])
```

## Security properties

- **Hardware-bound** — PRF output requires physical authenticator + biometric/PIN
- **Origin-bound** — phishing sites on different domains get useless PRF output
- **AAD-bound** — ciphertext tied to specific credential ID and version
- **No server trust** — relay is a dumb store, encryption is end-to-end
- **Memory hygiene** — PRF output and derived keys zeroed after use

## License

AGPL-3.0-or-later
