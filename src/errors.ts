export class KeytrError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'KeytrError'
  }
}

export class EncryptionError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'EncryptionError'
  }
}

export class DecryptionError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'DecryptionError'
  }
}

export class BlobParseError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'BlobParseError'
  }
}

export class WebAuthnError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'WebAuthnError'
  }
}

export class RelayError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'RelayError'
  }
}
