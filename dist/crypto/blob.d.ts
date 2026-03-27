import { type EncryptedNsecBlob } from '../types.js';
/** Serialize an EncryptedNsecBlob into a compact binary format */
export declare function serializeBlob(blob: EncryptedNsecBlob): Uint8Array;
/** Deserialize a binary blob back into its structured components */
export declare function deserializeBlob(data: Uint8Array): EncryptedNsecBlob;
//# sourceMappingURL=blob.d.ts.map