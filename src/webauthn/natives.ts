/**
 * Cached references to native WebAuthn API methods.
 *
 * Captured at module evaluation time (ESM import), before any user code
 * or third-party scripts can monkey-patch navigator.credentials.
 *
 * Mitigates POC-1: WebAuthn API monkey-patching attacks where an attacker
 * replaces navigator.credentials.create/get to intercept keyMaterial.
 */

/* eslint-disable @typescript-eslint/no-unnecessary-condition */

const _credentials = typeof navigator !== 'undefined' ? navigator.credentials : undefined

export const nativeCreate: typeof navigator.credentials.create | undefined =
  _credentials?.create?.bind(_credentials)

export const nativeGet: typeof navigator.credentials.get | undefined =
  _credentials?.get?.bind(_credentials)
