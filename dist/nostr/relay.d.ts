import type { Event } from 'nostr-tools/core';
/** Options for relay operations */
export interface RelayOptions {
    /** Connection/operation timeout in milliseconds. Defaults to 5000 (5 seconds). */
    timeout?: number;
}
/** Publish a signed keytr event to one or more relays */
export declare function publishKeytrEvent(event: Event, relayUrls: string[], options?: RelayOptions): Promise<void>;
/** Fetch all kind:30079 events for a given pubkey from relays */
export declare function fetchKeytrEvents(pubkey: string, relayUrls: string[], options?: RelayOptions): Promise<Event[]>;
//# sourceMappingURL=relay.d.ts.map