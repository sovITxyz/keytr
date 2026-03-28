# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Parallel relay operations** — `publishKeytrEvent` and `fetchKeytrEvents` now query all relays concurrently via `Promise.allSettled()` instead of sequentially, reducing worst-case latency from `N × timeout` to `1 × timeout`
- **Upgraded to noble/scure v2** — `@noble/ciphers` ^2.1.0, `@noble/hashes` ^2.0.0, `@scure/base` ^2.0.0

## [0.2.0] - 2026-03-27

### Added
- **Discoverable passkey login** — `discoverPasskey()` and `discoverAndLogin()` for zero-prior-knowledge login. The browser shows available passkeys, the user picks one, and the nsec is recovered without any npub input or localStorage state.
- `DiscoverOptions` and `DiscoverResult` types for the discoverable flow.
- Configurable timeouts for WebAuthn ceremonies (`timeout` option on `RegisterOptions` and `AuthenticateOptions`)
- Configurable timeouts for relay operations (`RelayOptions` with `timeout` parameter)
- Integration tests for relay publish/fetch roundtrips
- Integration tests for WebAuthn credential lifecycle (mocked)

### Changed
- **BREAKING:** `RegisterOptions.pubkey` is now a required field (hex-encoded 32-byte Nostr public key). The pubkey is stored as WebAuthn `user.id` to enable discoverable authentication.
- `setupKeytr()` and `addBackupGateway()` derive the pubkey automatically from the nsec — no change needed for callers of these high-level functions.
- Registration uses `hexToBytes(pubkey)` as `user.id` instead of `randomBytes(32)`.

### Migration
- New registrations work with discoverable login immediately.
- Old registrations (random `user.id`) still work with `loginWithKeytr(events)` but cannot use `discoverAndLogin()`. Users can re-register their passkey to upgrade.

## [0.1.0] - 2025-05-20

### Added
- NIP-K1 implementation: passkey-encrypted nsec keys for Nostr
- AES-256-GCM encryption with HKDF-SHA256 key derivation from WebAuthn PRF output
- `registerPasskey()` and `authenticatePasskey()` for WebAuthn credential management
- `encryptNsec()` / `decryptNsec()` with AAD binding to credential ID
- Binary blob serialization (93 bytes: version + IV + HKDF salt + ciphertext)
- Kind:30079 event building and parsing (`buildKeytrEvent` / `parseKeytrEvent`)
- Relay publish/fetch with multi-relay support and deduplication
- Nostr key utilities (nsec/npub encoding, key generation, hex conversion)
- High-level `setupKeytr()` and `loginWithKeytr()` convenience functions
- Federated gateway model for cross-client passkey compatibility
- Password fallback implementation (disabled from public API — unsafe for relay publication)
- Browser demo application
- NIP-K1 specification document

### Security
- PRF output and derived keys are zeroed after use
- AAD prevents credential/ciphertext substitution attacks
- Password fallback disabled pending safe UX design
