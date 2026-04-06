/**
 * Cached references to Uint8Array prototype methods.
 *
 * Captured at module evaluation time (ESM import), before any user code
 * or third-party scripts can pollute Uint8Array.prototype.
 *
 * Mitigates POC-3: Prototype pollution attacks where an attacker hijacks
 * .slice(), .set(), or .fill() to intercept key material mid-pipeline.
 */
const _slice = Uint8Array.prototype.slice;
const _set = Uint8Array.prototype.set;
const _fill = Uint8Array.prototype.fill;
/** Safe .slice() — immune to prototype pollution */
export function safeSlice(arr, begin, end) {
    return _slice.call(arr, begin, end);
}
/** Safe .set() — immune to prototype pollution */
export function safeSet(target, source, offset) {
    _set.call(target, source, offset);
}
/** Safe .fill() for zeroing sensitive data — immune to prototype pollution */
export function safeZero(arr) {
    _fill.call(arr, 0);
}
//# sourceMappingURL=builtins.js.map