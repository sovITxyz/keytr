import { Relay } from 'nostr-tools/relay';
import { KEYTR_EVENT_KIND } from '../types.js';
import { RelayError } from '../errors.js';
/** Publish a signed keytr event to one or more relays */
export async function publishKeytrEvent(event, relayUrls, options) {
    const timeout = options?.timeout ?? 5000;
    const errors = [];
    for (const url of relayUrls) {
        try {
            const relay = await Relay.connect(url);
            try {
                await Promise.race([
                    relay.publish(event),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Publish timed out')), timeout)),
                ]);
            }
            finally {
                relay.close();
            }
        }
        catch (err) {
            errors.push(`${url}: ${err.message}`);
        }
    }
    if (errors.length === relayUrls.length) {
        throw new RelayError(`Failed to publish to any relay:\n${errors.join('\n')}`);
    }
}
/** Fetch all kind:30079 events for a given pubkey from relays */
export async function fetchKeytrEvents(pubkey, relayUrls, options) {
    const timeout = options?.timeout ?? 5000;
    const events = [];
    const seen = new Set();
    for (const url of relayUrls) {
        try {
            const relay = await Relay.connect(url);
            try {
                const fetched = await new Promise((resolve) => {
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
                for (const event of fetched) {
                    if (!seen.has(event.id)) {
                        seen.add(event.id);
                        events.push(event);
                    }
                }
            }
            finally {
                relay.close();
            }
        }
        catch {
            // Skip failing relays, try others
        }
    }
    return events;
}
//# sourceMappingURL=relay.js.map