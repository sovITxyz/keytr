import { Relay } from 'nostr-tools/relay'
import type { Event } from 'nostr-tools/core'
import { KEYTR_EVENT_KIND } from '../types.js'
import { RelayError } from '../errors.js'

/** Options for relay operations */
export interface RelayOptions {
  /** Connection/operation timeout in milliseconds. Defaults to 5000 (5 seconds). */
  timeout?: number
}

async function connectWithTimeout(url: string, timeout: number): Promise<Relay> {
  return Promise.race([
    Relay.connect(url),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Connect to ${url} timed out`)), timeout)
    ),
  ])
}

/** Publish a signed keytr event to one or more relays */
export async function publishKeytrEvent(
  event: Event,
  relayUrls: string[],
  options?: RelayOptions
): Promise<void> {
  const timeout = options?.timeout ?? 5000

  const results = await Promise.allSettled(
    relayUrls.map(async (url) => {
      const relay = await connectWithTimeout(url, timeout)
      try {
        await Promise.race([
          relay.publish(event),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('Publish timed out')), timeout)
          ),
        ])
      } finally {
        relay.close()
      }
    })
  )

  const errors = results
    .map((r, i) => (r.status === 'rejected' ? `${relayUrls[i]}: ${r.reason.message}` : null))
    .filter((e): e is string => e !== null)

  if (errors.length === relayUrls.length) {
    throw new RelayError(`Failed to publish to any relay:\n${errors.join('\n')}`)
  }
}

/** Fetch all kind:30079 events for a given pubkey from relays */
export async function fetchKeytrEvents(
  pubkey: string,
  relayUrls: string[],
  options?: RelayOptions
): Promise<Event[]> {
  const timeout = options?.timeout ?? 5000

  const results = await Promise.allSettled(
    relayUrls.map(async (url) => {
      const relay = await connectWithTimeout(url, timeout)
      try {
        return await new Promise<Event[]>((resolve) => {
          const collected: Event[] = []
          const sub = relay.subscribe(
            [{ kinds: [KEYTR_EVENT_KIND], authors: [pubkey] }],
            {
              onevent(evt) {
                collected.push(evt)
              },
              oneose() {
                sub.close()
                resolve(collected)
              },
            }
          )
          setTimeout(() => {
            sub.close()
            resolve(collected)
          }, timeout)
        })
      } finally {
        relay.close()
      }
    })
  )

  const seen = new Set<string>()
  const events: Event[] = []
  for (const result of results) {
    if (result.status === 'fulfilled') {
      for (const event of result.value) {
        if (!seen.has(event.id)) {
          seen.add(event.id)
          events.push(event)
        }
      }
    }
  }

  return events
}
