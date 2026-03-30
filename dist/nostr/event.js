import { base64url } from '@scure/base';
import { KEYTR_EVENT_KIND, KEYTR_KIH_VERSION } from '../types.js';
import { KeytrError } from '../errors.js';
/** Build an unsigned kind:31777 event template for a passkey-encrypted nsec */
export function buildKeytrEvent(options) {
    const { credential, encryptedBlob, clientName } = options;
    const tags = [
        ['d', credential.credentialIdBase64url],
        ['rp', credential.rpId],
        ['algo', 'aes-256-gcm'],
        ['kdf', 'hkdf-sha256'],
        ['v', options.version ?? '1'],
    ];
    if (credential.transports.length > 0) {
        tags.push(['transports', ...credential.transports]);
    }
    if (clientName) {
        tags.push(['client', clientName]);
    }
    return {
        kind: KEYTR_EVENT_KIND,
        content: encryptedBlob,
        tags,
        created_at: Math.floor(Date.now() / 1000),
    };
}
/** Parse a kind:31777 event to extract credential info and encrypted blob */
export function parseKeytrEvent(event) {
    if (event.kind !== KEYTR_EVENT_KIND) {
        throw new KeytrError(`Expected kind ${KEYTR_EVENT_KIND}, got ${event.kind}`);
    }
    const getTag = (name) => event.tags.find(t => t[0] === name)?.[1];
    const credentialIdBase64url = getTag('d');
    if (!credentialIdBase64url) {
        throw new KeytrError('Missing "d" tag (credential ID)');
    }
    const rpId = getTag('rp');
    if (!rpId) {
        throw new KeytrError('Missing "rp" tag');
    }
    const version = parseInt(getTag('v') ?? '1', 10);
    const algorithm = getTag('algo') ?? 'aes-256-gcm';
    const kdf = getTag('kdf') ?? 'hkdf-sha256';
    const transportsTag = event.tags.find(t => t[0] === 'transports');
    const transports = transportsTag ? transportsTag.slice(1) : [];
    const clientName = getTag('client');
    let credentialId;
    try {
        credentialId = base64url.decode(credentialIdBase64url);
    }
    catch {
        throw new KeytrError('Invalid credential ID encoding in "d" tag');
    }
    const mode = version === KEYTR_KIH_VERSION ? 'kih' : 'prf';
    return {
        credentialIdBase64url,
        credentialId,
        rpId,
        encryptedBlob: event.content,
        version,
        algorithm,
        kdf,
        transports,
        clientName,
        mode,
    };
}
//# sourceMappingURL=event.js.map