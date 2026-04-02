# Integration Guide

How to wire keytr into a Nostr client's auth flow, session restore, and credential management. This guide covers the recommended patterns for production use — fast login, graceful fallbacks, and credential indexing that improves over time.

The canonical implementation of these patterns is [BIES's keytrService.js](https://github.com/sovITxyz/BIES/blob/main/src/services/keytrService.js).

---

## The Three-Tier Login Pattern

keytr exposes two login primitives: `loginWithKeytr(events)` (known credential) and `discover(relays)` (discoverable, auto-detects PRF vs KiH). A production client should combine these into a **three-tier fallback** that gets faster over time as it builds a local credential index:

```
Tier 1: Credential index (app-managed)
  └─ Have a stored pubkey from keytr? → fetchKeytrEvents(pubkey) → loginWithKeytr(events)
  └─ Fast: targeted relay query, one biometric prompt, 2–5 seconds

Tier 2: Cached user pubkey (app's user store)
  └─ No credential index, but app knows the user's pubkey from a prior login?
  └─ Same flow as Tier 1, auto-index the credential for next time

Tier 3: Discoverable (cold start)
  └─ No local state at all → discoverAndLogin(relays)
  └─ Browser shows passkey picker, user selects identity
  └─ Auto-index the credential for next time
```

Every tier ends with a single biometric prompt. The difference is **how the client finds the right kind:31777 events** — by targeted pubkey query (tiers 1–2) or by recovering the pubkey from the passkey itself (tier 3).

### Why three tiers?

Discoverable login (`discover`) works from zero state, but it's the slowest path — it triggers a WebAuthn discovery assertion, auto-detects the mode (PRF vs KiH), then fetches the encrypted event from relays. If the client already knows the pubkey (from its own user store or a credential index), it can skip discovery and go straight to a targeted relay query with a single assertion.

The three-tier pattern means:
- **First login** on a new device hits tier 3 (discoverable). Slow but works.
- **Second login** hits tier 1 or 2 (indexed). Fast.
- **Login after clearing keytr data but not app data** hits tier 2 (app's user store). Still fast.

**Note on KiH mode**: Tiers 1 and 2 (known pubkey → `fetchKeytrEvents` → `loginWithKeytr`) only work for PRF-mode credentials. KiH credentials don't store the pubkey in `userHandle`, so they always go through tier 3 (discoverable). The `discover()` API handles this automatically.

---

## Credential Indexing

keytr itself does not manage a credential index — that's the consuming app's responsibility. The index is a lightweight mapping of pubkeys that have keytr credentials, stored in the app's own persistence layer (typically localStorage).

### What to store

Store the minimum needed for fast-path login:

```typescript
interface CredentialEntry {
  pubkey: string     // hex-encoded Nostr public key
  createdAt: string  // ISO 8601 timestamp
}
```

You do **not** need to store credential IDs, rpIds, or encrypted blobs — those live on relays. The index just answers: "does this user have keytr credentials, and what pubkey should I query for?"

### When to update the index

- **After registration** (`setup`, `setupKeytr`, or `registerPasskey`): add the pubkey.
- **After discoverable login** (`discover` or `discoverAndLogin`): add the recovered pubkey (auto-upgrade from tier 3 to tier 1).
- **After tier 2 login**: add the pubkey from the app's user store (auto-upgrade from tier 2 to tier 1).
- **When the user removes their passkey**: remove the entry.

### Example: localStorage index

```javascript
const STORAGE_KEY = 'myapp_keytr_credentials'

function getCredentialIndex() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [] }
  catch { return [] }
}

function addToIndex(pubkey) {
  const index = getCredentialIndex().filter(c => c.pubkey !== pubkey)
  index.push({ pubkey, createdAt: new Date().toISOString() })
  localStorage.setItem(STORAGE_KEY, JSON.stringify(index))
}

function hasCredential(pubkey) {
  return getCredentialIndex().some(c => c.pubkey === pubkey)
}

function removeFromIndex(pubkey) {
  const index = getCredentialIndex().filter(c => c.pubkey !== pubkey)
  localStorage.setItem(STORAGE_KEY, JSON.stringify(index))
}
```

---

## The userHandle: Mode Detection

During passkey registration, keytr stores different data in the WebAuthn `user.id` depending on the mode:

### PRF mode (32 bytes)

```
userHandle = raw 32-byte x-only Nostr public key
```

This is the same value as the `pubkey` field in Nostr events, just in raw bytes instead of hex. The pubkey enables relay lookup by author during discoverable login.

### KiH mode (33 bytes)

```
userHandle = [0x03 || random_key(32)]
```

The first byte (`0x03`) is a mode marker. The remaining 32 bytes are the encryption key. No pubkey is stored — it's recovered by deriving from the nsec after decryption.

### Mode detection

keytr detects the mode from the `userHandle` length:
- **32 bytes** → PRF mode (pubkey)
- **33 bytes, byte[0] === 0x03** → KiH mode (encryption key)

The unified `discover()` and `unifiedDiscover()` APIs handle this automatically. Apps should not need to inspect `userHandle` directly.

### How apps should use it

After a successful `discover()` call, the returned `pubkey` is available regardless of mode (KiH derives it after decryption). Use it for:

1. **Credential indexing**: Store the pubkey so future PRF-mode logins can skip discovery.
2. **User identification**: Load the user's profile, check session state.

For KiH-mode credentials, relay lookup uses `#d` tag queries instead of pubkey author queries — this is handled internally by `discover()`.

---

## fetchKeytrEvents: Not Just for keytr's Index

`fetchKeytrEvents(pubkey, relays)` queries relays for kind:31777 events authored by the given pubkey. The pubkey parameter can come from **anywhere** — it's not limited to keytr's own credential index or discoverable flow.

Common sources for the pubkey:

| Source | Example | Tier |
|--------|---------|------|
| App's credential index | `localStorage['myapp_keytr_credentials']` | 1 |
| App's user store | `localStorage['myapp_user'].nostrPubkey` | 2 |
| URL parameter | `?pubkey=abc123...` | 2 |
| NIP-05 lookup | `alice@example.com` → pubkey | 2 |
| userHandle from discoverable auth | `discoverPasskey().pubkey` | 3 |

If your app already knows the user's pubkey from a previous login (via any method — extension, nsec, bunker, etc.), you can use that pubkey to fetch keytr events and offer passkey login without discoverable auth:

```javascript
// User previously logged in via NIP-07 extension, app cached their pubkey
const cachedPubkey = myAppUserStore.getUser()?.nostrPubkey

if (cachedPubkey) {
  const events = await fetchKeytrEvents(cachedPubkey, relays)
  if (events.length > 0) {
    // User has keytr credentials — offer "Login with Passkey" as a fast path
    const { nsecBytes } = await loginWithKeytr(events)
  }
}
```

This is how tier 2 works — the pubkey comes from the app's own data, not from keytr.

---

## Full Login Implementation

Putting it all together — a complete login function with three-tier fallback:

```javascript
import {
  fetchKeytrEvents,
  loginWithKeytr,
  discover,
  encodeNsec,
} from '@sovit.xyz/keytr'

const RELAYS = ['wss://relay.damus.io', 'wss://relay.primal.net', 'wss://nos.lol']

async function loginWithPasskey() {
  // ── Tier 1: credential index ──────────────────────────────────
  const indexed = getCredentialIndex()

  if (indexed.length > 0) {
    for (const { pubkey } of indexed) {
      const events = await fetchKeytrEvents(pubkey, RELAYS)
      if (events.length > 0) {
        const { nsecBytes } = await loginWithKeytr(events)
        try {
          return encodeNsec(nsecBytes)
        } finally {
          nsecBytes.fill(0)
        }
      }
    }
    // Index exists but no events found — fall through
  }

  // ── Tier 2: app's cached user pubkey ──────────────────────────
  try {
    const cachedUser = JSON.parse(localStorage.getItem('myapp_user'))
    if (cachedUser?.pubkey) {
      const events = await fetchKeytrEvents(cachedUser.pubkey, RELAYS)
      if (events.length > 0) {
        const { nsecBytes } = await loginWithKeytr(events)
        try {
          // Auto-upgrade: index the credential for tier 1 next time
          if (!hasCredential(cachedUser.pubkey)) addToIndex(cachedUser.pubkey)
          return encodeNsec(nsecBytes)
        } finally {
          nsecBytes.fill(0)
        }
      }
    }
  } catch { /* fall through to discoverable */ }

  // ── Tier 3: discoverable (auto-detects PRF vs KiH) ────────────
  const { nsecBytes, pubkey } = await discover(RELAYS)
  try {
    // Auto-upgrade: index the credential for tier 1 next time
    if (pubkey && !hasCredential(pubkey)) addToIndex(pubkey)
    return encodeNsec(nsecBytes)
  } finally {
    nsecBytes.fill(0)
  }
}
```

---

## Session Restore

When a user refreshes the page or reopens the app, the nsec is gone — keytr never persists it. The app needs to re-acquire the signing key when it's needed again.

### Lazy re-acquisition

Don't prompt for a passkey immediately on page load. Instead, defer re-acquisition until the app actually needs to sign something:

```javascript
class NostrSigner {
  #nsecBytes = null

  async sign(event) {
    if (!this.#nsecBytes) {
      await this.#reacquire()
    }
    return finalizeEvent(event, this.#nsecBytes)
  }

  async #reacquire() {
    // Only attempt if the user's last login method was passkey
    if (localStorage.getItem('login_method') !== 'passkey') return
    if (!hasCredential()) return

    const nsec = await loginWithPasskey()  // three-tier login from above
    this.#nsecBytes = decodeNsec(nsec)
  }

  clear() {
    if (this.#nsecBytes) {
      this.#nsecBytes.fill(0)
      this.#nsecBytes = null
    }
  }
}
```

This approach:
- **Avoids unnecessary prompts**: if the user only reads content, no biometric is triggered.
- **Triggers naturally**: the first action that requires signing (post, like, follow) prompts the passkey.
- **Respects login method**: only attempts passkey re-acquisition if that's how the user logged in.

### Eager re-acquisition

For apps where signing is expected immediately (e.g., a chat client), trigger re-acquisition on page load:

```javascript
window.addEventListener('load', async () => {
  if (localStorage.getItem('login_method') === 'passkey' && hasCredential()) {
    await loginWithPasskey()
  }
})
```

---

## Registration and Passkey Save Flow

### New user setup

For users who don't have a Nostr identity yet:

```javascript
import { setup, publishKeytrEvent, nsecToHexPubkey } from '@sovit.xyz/keytr'
import { finalizeEvent } from 'nostr-tools/pure'

// Tries PRF first, falls back to KiH for password manager extensions
const { credential, encryptedBlob, eventTemplate, nsecBytes, npub, mode } = await setup({
  userName: 'My App User',
  userDisplayName: 'My App User',
  rpId: 'keytr.org',             // use a gateway for cross-client access
  clientName: 'my-app',
})

console.log(`Registered in ${mode} mode`) // 'prf' or 'kih'

// Sign and publish
const signedEvent = finalizeEvent(eventTemplate, nsecBytes)
await publishKeytrEvent(signedEvent, RELAYS)

// Index the credential locally
addToIndex(nsecToHexPubkey(nsecBytes))
```

### Existing user: post-login passkey save

The more common case — a user who already has an nsec (from extension, seed phrase, etc.) and wants to add passkey access:

```javascript
import {
  registerPasskey,
  encryptNsec,
  buildKeytrEvent,
  publishKeytrEvent,
  decodeNsec,
  KEYTR_GATEWAYS,
} from '@sovit.xyz/keytr'

async function savePasskey(nsecBech32, pubkey, signer) {
  const nsecBytes = decodeNsec(nsecBech32)
  const rpId = KEYTR_GATEWAYS[0]  // 'keytr.org'

  const { credential, prfOutput } = await registerPasskey({
    userName: pubkey.slice(0, 16),
    userDisplayName: 'Nostr User',
    pubkey,
    rpId,
    rpName: rpId,
  })

  let encryptedBlob
  try {
    encryptedBlob = encryptNsec({
      nsecBytes,
      prfOutput,
      credentialId: credential.credentialId,
    })
  } finally {
    prfOutput.fill(0)
  }

  const eventTemplate = buildKeytrEvent({
    credential,
    encryptedBlob,
    clientName: 'my-app',
  })

  const signedEvent = await signer.signEvent({ ...eventTemplate, pubkey })
  await publishKeytrEvent(signedEvent, RELAYS)

  addToIndex(pubkey)
}
```

### Backup gateway

After saving to the primary gateway, offer a second prompt for redundancy:

```javascript
import { addBackupGateway, publishKeytrEvent } from '@sovit.xyz/keytr'

const { credential, encryptedBlob, eventTemplate } = await addBackupGateway(nsecBytes, {
  rpId: KEYTR_GATEWAYS[1],  // 'nostkey.org'
  rpName: 'nostkey.org',
  userName: pubkey.slice(0, 16),
  userDisplayName: 'Nostr User',
  clientName: 'my-app',
})

const signedEvent = await signer.signEvent({ ...eventTemplate, pubkey })
await publishKeytrEvent(signedEvent, RELAYS)
```

This creates a second kind:31777 event with a different `d` tag (different credential ID) and different `rp` tag (`nostkey.org`). If `keytr.org` goes down, the user can still authenticate via `nostkey.org`.

---

## Error Handling

### Password manager extension interference

Password manager extensions (Bitwarden, 1Password, Dashlane) can intercept WebAuthn calls and may reject cross-origin rpIds if they lack Related Origin Request support. Detect this and show a targeted message:

```javascript
function isExtensionInterference(error) {
  const msg = error?.message?.toLowerCase() || ''
  return (
    msg.includes('relying party id') &&
    (msg.includes('registrable domain') || msg.includes('equal to the current domain'))
  )
}

try {
  await loginWithPasskey()
} catch (err) {
  if (isExtensionInterference(err)) {
    showMessage(
      'A password manager extension may be blocking passkey authentication. ' +
      'Try disabling passkey/WebAuthn support in your password manager settings.'
    )
  }
}
```

See [Architecture: Password Manager Extensions](architecture.md#password-manager-extensions-intercepting-webauthn) for details.

### PRF support detection

Check for PRF support early if you need to inform the user which mode will be used. Note that the unified `setup()` API handles this automatically — it tries PRF first and falls back to KiH:

```javascript
import { checkPrfSupport } from '@sovit.xyz/keytr'

const { supported, platformAuthenticator, reason } = await checkPrfSupport()

if (!supported) {
  // PRF unavailable — setup() will use KiH mode automatically
  // You can still show passkey UI, just inform the user
  console.log('PRF not available, will use KiH mode:', reason)
}
```

### Comprehensive capability detection

For a full picture of what the browser supports, use `checkCapabilities()`:

```javascript
import { checkCapabilities } from '@sovit.xyz/keytr'

const caps = await checkCapabilities()

if (caps.conditionalMediation) {
  // Can use passkey autofill instead of modal picker
}
if (caps.relatedOrigins) {
  // Cross-domain passkey use works (federated gateways)
} else {
  // Firefox: offer separate registration per gateway
}
if (caps.signalApi) {
  // Can tell authenticators to clean up revoked credentials
}
```

Uses `PublicKeyCredential.getClientCapabilities()` (Chrome 132+) when available, with feature detection fallback for older browsers.

### SSR safety

All WebAuthn functions (`registerPasskey`, `registerKihPasskey`, `authenticatePasskey`, `discoverPasskey`, `unifiedDiscover`) throw `WebAuthnError` immediately in non-browser environments. For SSR frameworks (Next.js, Nuxt), use `ensureBrowser()` to gate UI:

```javascript
import { ensureBrowser } from '@sovit.xyz/keytr'

function PasskeyButton() {
  try {
    ensureBrowser()
    return <button onClick={handlePasskey}>Login with Passkey</button>
  } catch {
    return null  // Don't render passkey UI on server
  }
}
```

---

## Conditional UI (Passkey Autofill)

Instead of the modal passkey picker, you can show passkey suggestions inline in a text field. This requires:
1. An `<input>` with `autocomplete="webauthn"` in the DOM
2. A browser that supports conditional mediation (Chrome 108+, Safari 16+, Edge 108+, Firefox 119+)

```javascript
import { discover, checkCapabilities } from '@sovit.xyz/keytr'

const caps = await checkCapabilities()

if (caps.conditionalMediation) {
  // Show passkey suggestions in the username input
  const { nsecBytes, pubkey, mode } = await discover(RELAYS, {
    mediation: 'conditional',
  })
}
```

Check support with `checkCapabilities().conditionalMediation` before using, as unsupported browsers will ignore the option and show the modal picker.

---

## Backup Eligibility Flags

After registration, `KeytrCredential` includes backup flags parsed from `authenticatorData`:

```javascript
const { credential } = await setup({ ... })

if (credential.backupEligible === false) {
  // Device-bound credential — warn the user it won't sync
  showWarning('This passkey is stored on this device only. Consider adding a backup gateway.')
}

if (credential.backupState === true) {
  // Credential is actively backed up / synced
}
```

- `backupEligible` (BE flag): Whether the authenticator supports multi-device sync
- `backupState` (BS flag): Whether the credential is currently backed up

Both are `undefined` if the browser doesn't expose `getAuthenticatorData()`.

---

## Signal API (Credential Lifecycle)

The WebAuthn Signal API (Chrome 132+) lets you tell authenticators about credential lifecycle changes. All functions return `true` if the signal was sent, `false` if the API is unavailable:

```javascript
import {
  signalUnknownCredential,
  signalAllAcceptedCredentialIds,
  signalCurrentUserDetails,
} from '@sovit.xyz/keytr'

// User revoked a passkey — tell authenticators to remove it
await signalUnknownCredential('keytr.org', credentialId)

// Sync the full set of valid credential IDs for a user
await signalAllAcceptedCredentialIds('keytr.org', userId, [credId1, credId2])

// Update the user's display name shown in the passkey picker
await signalCurrentUserDetails('keytr.org', userId, 'alice', 'Alice')
```

These are no-ops on browsers without Signal API support — safe to call unconditionally.

---

## Authenticator Hints

WebAuthn Level 3 adds `hints` to guide the browser toward the right authenticator type. Pass these through keytr's registration and authentication options:

```javascript
await setup({
  userName: 'alice',
  userDisplayName: 'Alice',
  hints: ['client-device'],  // prefer platform authenticator over security key
})

await discover(RELAYS, {
  hints: ['hybrid'],  // prefer phone-as-authenticator flow
})
```

Available hints: `'security-key'`, `'client-device'`, `'hybrid'`. Unsupported browsers ignore the option.

---

## Relay Timeouts

High-level functions accept `relayOptions` to configure relay operation timeouts:

```javascript
await discover(RELAYS, {
  relayOptions: { timeout: 15000 },  // 15 seconds instead of default 5
})
```

Useful for slow networks or Tor relays. Low-level functions (`publishKeytrEvent`, `fetchKeytrEvents`, `fetchKeytrEventByDTag`) already accept `RelayOptions` directly.

---

## Checklist

Integration checklist for client developers:

- [ ] **Credential index**: Maintain a local index of pubkeys with keytr credentials
- [ ] **Three-tier login**: Implement the fallback chain (index → app user store → discoverable)
- [ ] **Auto-indexing**: After discoverable or tier-2 login, add the pubkey to the credential index
- [ ] **Memory hygiene**: Zero `nsecBytes` in `finally` blocks after use
- [ ] **Session restore**: Re-acquire signing keys lazily or eagerly based on your app's needs
- [ ] **Backup gateway**: Offer registration on a second gateway (`nostkey.org`) for redundancy
- [ ] **Extension detection**: Detect password manager interference and show a targeted hint
- [ ] **Capability check**: Use `checkCapabilities()` to detect PRF, conditional UI, ROR, and Signal API support
- [ ] **Backup flags**: Check `credential.backupEligible` and warn if the passkey won't sync
- [ ] **Signal API**: Call `signalUnknownCredential()` when users revoke passkeys
- [ ] **Gateway origin**: Submit a PR to add your domain to the gateway's `/.well-known/webauthn`
