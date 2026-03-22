export class NostkeyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NostkeyError'
  }
}

export class PrfNotSupportedError extends NostkeyError {
  constructor(reason?: string) {
    super(reason ?? 'WebAuthn PRF extension is not supported by this authenticator')
    this.name = 'PrfNotSupportedError'
  }
}

export class EncryptionError extends NostkeyError {
  constructor(message: string) {
    super(message)
    this.name = 'EncryptionError'
  }
}

export class DecryptionError extends NostkeyError {
  constructor(message: string) {
    super(message)
    this.name = 'DecryptionError'
  }
}

export class BlobParseError extends NostkeyError {
  constructor(message: string) {
    super(message)
    this.name = 'BlobParseError'
  }
}

export class WebAuthnError extends NostkeyError {
  constructor(message: string) {
    super(message)
    this.name = 'WebAuthnError'
  }
}

export class RelayError extends NostkeyError {
  constructor(message: string) {
    super(message)
    this.name = 'RelayError'
  }
}
