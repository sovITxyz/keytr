# keytr Roadmap

## Current State: NIP-K1 (v0.2.x)

keytr implements NIP-K1 — passkey-encrypted private keys. A user's nsec is encrypted with the WebAuthn PRF extension and published to Nostr relays as a kind:30079 event. Any device with the synced passkey can decrypt it in one biometric tap.

**What's shipping today:**
- Full NIP-K1 implementation (encrypt, decrypt, event publish/fetch)
- Discoverable login (no prior pubkey needed)
- Parallel relay operations
- Cross-gateway support via Related Origin Requests
- YubiKey compatibility (PRF assertion fallback)
- Federated gateways: keytr.org + nostkey.org

---

## Backup & Resilience Enhancements

### Problem

K1 stores the encrypted nsec on Nostr relays. If all relays purge the kind:30079 event, the user has a working passkey but nothing to decrypt — login fails permanently. The encrypted event is safe to store anywhere (can't be decrypted without the passkey's PRF output), so the mitigation is redundant storage across independent layers.

See [architecture.md — Backup & Resilience](architecture.md#backup--resilience) for the full design and current backup layers (relay redundancy, multi-gateway, client cache, event export, HTTP fallback).

### WebAuthn largeBlob — Self-Contained Passkey Recovery

**Status**: Blocked on ecosystem adoption

The ideal end-state: store the signed kind:30079 event inside the passkey itself via the WebAuthn `largeBlob` extension. One passkey carries both the decryption key (PRF) and the encrypted payload. No relay, no file, no external storage.

**Current compatibility (as of March 2026):**

| Authenticator | largeBlob | Notes |
|---|---|---|
| YubiKey 5 (firmware 5.7+) | Yes | CTAP 2.1, max 4096 bytes |
| iCloud Keychain | Yes | Since iOS 17 / macOS Sonoma / Safari 17 |
| Google Password Manager | **No** | Supports PRF but not largeBlob |
| Windows Hello | **No** | No credential management or largeBlob |
| 1Password | **No** | No largeBlob support |
| Bitwarden | **No** | No largeBlob support |
| Dashlane | **No** | No largeBlob support |

| Browser | largeBlob | Notes |
|---|---|---|
| Chrome | Yes | Depends on authenticator support |
| Safari 17+ | Yes | Only with iCloud Keychain |
| Firefox | Unclear | PRF support added in 148+, largeBlob not confirmed |

Google Password Manager + Windows Hello = majority of passkey users. Until they add largeBlob, this can't be a relied-upon layer.

**Implementation plan (when adoption is sufficient):**

1. At registration: detect `largeBlob` support via `getClientExtensionResults()`
2. If supported: write the signed kind:30079 event JSON into the credential's largeBlob
3. At login: if relay fetch returns no events, attempt `largeBlob` read before giving up
4. Never depend on it — treat as an opportunistic bonus layer alongside existing backups

### Client-Side Cache & Event Export

**Status**: Ready to implement

These don't require any new WebAuthn features — they're client-side patterns that any keytr integration can adopt today:

- **Local cache**: Store kind:30079 events in localStorage/IndexedDB after login; check before relay fetch
- **Event export**: Let users download the signed event as JSON or QR code for offline recovery

These should be documented as recommended patterns in the integration guide and optionally provided as helper utilities in the library.

### HTTP Fallback Endpoint

**Status**: Design phase

Gateway operators (keytr.org, nostkey.org) could serve events at:

```
GET https://keytr.org/.well-known/nostr/k1/<hex-pubkey>
```

Simple HTTP GET, no Nostr protocol. Clients try this after relay fetch fails. Requires gateway-side infrastructure to ingest and serve kind:30079 events.

---

## Future Direction: NIP-K2 — Passseeds

NIP-K2 introduces **passseeds** — deterministic key derivation from passkeys. Instead of encrypting an existing nsec, the passkey PRF output IS the seed that derives the nsec. No relay needed for key material.

### Why K2

K1 works well for users who already have a Nostr identity or need relay-backed recovery. But for onboarding new users, K1 has unnecessary friction:

1. Generate random nsec → why? The user doesn't care about the raw key
2. Encrypt and publish to relays → extra infrastructure dependency
3. Fetch on login → requires relay availability

K2 eliminates all of this. Register a passkey, derive an identity, done. The relay becomes optional — only needed for social features, not for key recovery.

### Implementation Path

#### Phase 1: Core Derivation

Add the passseed derivation layer alongside the existing K1 crypto:

```
src/crypto/
  ├── kdf.ts           # existing K1 key derivation
  ├── encrypt.ts       # existing K1 encryption
  ├── decrypt.ts       # existing K1 decryption
  ├── blob.ts          # existing K1 blob serialization
  └── passseed.ts      # NEW: HKDF derivation from PRF → nsec
```

New constants in types.ts:

```typescript
export const PASSSEED_VERSION = 1
export const PASSSEED_EVENT_KIND = 30080
export const PASSSEED_PRF_SALT = new TextEncoder().encode('keytr-seed-v1')
export const PASSSEED_HKDF_SALT = new TextEncoder().encode('passseed-v1')
export const PASSSEED_HKDF_INFO = 'keytr passseed v1'
```

Core function:

```typescript
function deriveNsec(prfOutput: Uint8Array): Uint8Array {
  return hkdf(sha256, prfOutput, PASSSEED_HKDF_SALT, PASSSEED_HKDF_INFO, 32)
}
```

#### Phase 2: WebAuthn Integration

Add K2-specific registration and discovery:

```
src/webauthn/
  ├── register.ts       # update: K2 registration with marker user.id
  ├── authenticate.ts   # update: K2 discoverable flow
  └── prf.ts            # update: K2 PRF salt builders
```

Key changes:
- `registerPassseed()` — creates credential with fixed `PASSSEED_USER_ID` marker as `user.id` and K2 PRF salt
- `discoverPasskey()` — routes to K1 or K2 based on returned `userHandle`

#### Phase 3: High-Level Flows

New public API functions in index.ts:

```typescript
// K2: Register passkey + derive identity (no relay needed)
setupPassseed(options: PassseedSetupOptions): Promise<PassseedResult>

// K2: Discoverable login — derive nsec from PRF
discoverAndLoginPassseed(options: PassseedLoginOptions): Promise<LoginResult>

// Dual: Discoverable login that auto-routes K1 or K2
discoverAndLoginAuto(options: AutoLoginOptions): Promise<LoginResult>

// Hybrid: Derive via K2, then encrypt via K1 as backup
setupPassseedWithBackup(options: HybridSetupOptions): Promise<HybridResult>
```

#### Phase 4: Marker Events

Optional kind:30080 events for cross-client discovery:

```
src/nostr/
  ├── event.ts          # update: buildPassseedMarker(), parsePassseedMarker()
  └── relay.ts          # update: publish/fetch kind:30080
```

### What Doesn't Change

- NIP-K1 stays fully supported — K2 is additive, not a replacement
- Existing kind:30079 events remain valid indefinitely
- Same gateway infrastructure (keytr.org, nostkey.org)
- Same authenticator compatibility (PRF is the shared requirement)
- Same @noble/hashes HKDF — just different salt/info constants

### Decision Points

These are open questions to resolve before implementation:

**1. Default for new users**
Should `setupKeytr()` default to K2 (passseed) for new users and K1 for import? Or keep K1 as default with K2 opt-in?

**2. Auto-backup**
Should `setupPassseed()` automatically create a K1 backup event? This adds relay dependency but protects against credential loss. Could be a recommended default that users can opt out of.

**3. Marker event publishing**
Should marker events be published by default? They reveal that a pubkey was created via passseed (metadata leak). But without them, other clients can't offer passseed login hints.

**4. Naming**
Public API naming: `setupPassseed()` vs `setupKeytrSeed()` vs `deriveIdentity()`. The name should communicate "your passkey becomes your key" without jargon.

**5. Multi-credential UX**
When a user has both K1 and K2 credentials, the passkey picker shows both. How should the client present this? Should it label them differently? The `user.name` field could include a suffix like "(passseed)" vs "(encrypted)".

### Compatibility Matrix

Both K1 and K2 require PRF. The authenticator support is identical:

| Authenticator | PRF | K1 | K2 | Notes |
|---|---|---|---|---|
| iCloud Keychain | Yes | Yes | Yes | Full sync across Apple devices |
| Google Password Manager | Yes | Yes | Yes | Full sync across Android/Chrome |
| Windows Hello | Yes | Yes | Yes | Device-bound, no sync |
| YubiKey 5 | Yes* | Yes | Yes | 25 resident key slots, PRF on assertion only |
| Bitwarden / 1Password / Dashlane | No | No | No | No PRF support, intercept WebAuthn |

### Timeline Considerations

K2 is a protocol-level addition. Before implementation:

1. **Finalize NIP-K2 spec** — the draft is at `nip/nip-k2.md`
2. **Community review** — get feedback on the marker event format, user.id marker approach, and K1/K2 coexistence
3. **Prototype** — build `deriveNsec()` + passseed registration in a branch
4. **Test cross-platform** — verify PRF salt independence (K1 salt vs K2 salt produce different outputs on same credential)
5. **Ship behind feature flag** — add K2 to the library as opt-in before making it a default flow
