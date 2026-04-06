import { type KeytrEventTemplate, type KeytrCredential } from '../types.js';
interface BuildEventOptions {
    credential: KeytrCredential;
    encryptedBlob: string;
    clientName?: string;
    /** AAD version byte. Defaults to KEYTR_VERSION. Strategies may override. */
    version?: number;
}
/** Build an unsigned kind:31777 event template for a passkey-encrypted nsec */
export declare function buildKeytrEvent(options: BuildEventOptions): KeytrEventTemplate;
export interface ParsedKeytrEvent {
    credentialIdBase64url: string;
    credentialId: Uint8Array;
    rpId: string;
    encryptedBlob: string;
    version: number;
    algorithm: string;
    kdf: string;
    transports: string[];
    clientName?: string;
}
/** Parse a kind:31777 event to extract credential info and encrypted blob */
export declare function parseKeytrEvent(event: {
    kind: number;
    content: string;
    tags: string[][];
}): ParsedKeytrEvent;
export {};
//# sourceMappingURL=event.d.ts.map