/**
 * Cached references to Uint8Array prototype methods.
 *
 * Captured at module evaluation time (ESM import), before any user code
 * or third-party scripts can pollute Uint8Array.prototype.
 *
 * Mitigates POC-3: Prototype pollution attacks where an attacker hijacks
 * .slice(), .set(), or .fill() to intercept key material mid-pipeline.
 */
/** Safe .slice() — immune to prototype pollution */
export declare function safeSlice(arr: Uint8Array, begin?: number, end?: number): Uint8Array;
/** Safe .set() — immune to prototype pollution */
export declare function safeSet(target: Uint8Array, source: ArrayLike<number>, offset?: number): void;
/** Safe .fill() for zeroing sensitive data — immune to prototype pollution */
export declare function safeZero(arr: Uint8Array): void;
//# sourceMappingURL=builtins.d.ts.map