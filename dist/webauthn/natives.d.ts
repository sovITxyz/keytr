/**
 * Cached references to native WebAuthn API methods.
 *
 * Captured at module evaluation time (ESM import), before any user code
 * or third-party scripts can monkey-patch navigator.credentials.
 *
 * Mitigates POC-1: WebAuthn API monkey-patching attacks where an attacker
 * replaces navigator.credentials.create/get to intercept keyMaterial.
 */
export declare const nativeCreate: typeof navigator.credentials.create | undefined;
export declare const nativeGet: typeof navigator.credentials.get | undefined;
//# sourceMappingURL=natives.d.ts.map