import { Relay } from 'nostr-tools/relay';
import { KEYTR_EVENT_KIND } from '../types.js';
import { RelayError } from '../errors.js';
async function connectWithTimeout(url, timeout) {
    return Promise.race([
        Relay.connect(url),
        new Promise((_, reject) => setTimeout(() => reject(new Error(`Connect to ${url} timed out`)), timeout)),
    ]);
}
/** Publish a signed keytr event to one or more relays */
export async function publishKeytrEvent(event, relayUrls, options) {
    const timeout = options?.timeout ?? 5000;
    const results = await Promise.allSettled(relayUrls.map(async (url) => {
        const relay = await connectWithTimeout(url, timeout);
        try {
            await Promise.race([
                relay.publish(event),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Publish timed out')), timeout)),
            ]);
        }
        finally {
            relay.close();
        }
    }));
    const errors = results
        .map((r, i) => (r.status === 'rejected' ? `${relayUrls[i]}: ${r.reason.message}` : null))
        .filter((e) => e !== null);
    if (errors.length === relayUrls.length) {
        throw new RelayError(`Failed to publish to any relay:\n${errors.join('\n')}`);
    }
}
/** Fetch all kind:30079 events for a given pubkey from relays */
export async function fetchKeytrEvents(pubkey, relayUrls, options) {
    const timeout = options?.timeout ?? 5000;
    const results = await Promise.allSettled(relayUrls.map(async (url) => {
        const relay = await connectWithTimeout(url, timeout);
        try {
            return await new Promise((resolve) => {
                const collected = [];
                const sub = relay.subscribe([{ kinds: [KEYTR_EVENT_KIND], authors: [pubkey] }], {
                    onevent(evt) {
                        collected.push(evt);
                    },
                    oneose() {
                        sub.close();
                        resolve(collected);
                    },
                });
                setTimeout(() => {
                    sub.close();
                    resolve(collected);
                }, timeout);
            });
        }
        finally {
            relay.close();
        }
    }));
    const seen = new Set();
    const events = [];
    for (const result of results) {
        if (result.status === 'fulfilled') {
            for (const event of result.value) {
                if (!seen.has(event.id)) {
                    seen.add(event.id);
                    events.push(event);
                }
            }
        }
    }
    return events;
}
//# sourceMappingURL=relay.js.map