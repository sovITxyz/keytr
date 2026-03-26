# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Configurable timeouts for WebAuthn ceremonies (`timeout` option on `RegisterOptions` and `AuthenticateOptions`)
- Configurable timeouts for relay operations (`RelayOptions` with `timeout` parameter)
- Integration tests for relay publish/fetch roundtrips
- Integration tests for WebAuthn credential lifecycle (mocked)

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
