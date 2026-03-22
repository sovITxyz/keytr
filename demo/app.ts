import {
  checkPrfSupport,
  registerPasskey,
  authenticatePasskey,
  encryptNsec,
  decryptNsec,
  generateNsec,
  encodeNsec,
  decodeNsec,
  nsecToNpub,
  buildNostkeyEvent,
  parseNostkeyEvent,
  encryptNsecWithPassword,
  decryptNsecFromPassword,
} from '../src/index.js'

// DOM elements
const $ = (id: string) => document.getElementById(id)!
const supportCheck = $('support-check')
const setupSection = $('setup-section')
const loginSection = $('login-section')
const passwordSection = $('password-section')
const logEl = $('log')

function log(msg: string, type: 'info' | 'success' | 'error' = 'info') {
  const entry = document.createElement('div')
  entry.className = `entry ${type}`
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`
  logEl.prepend(entry)
}

// Check support on load
async function init() {
  log('Checking WebAuthn PRF support...')
  const support = await checkPrfSupport()

  if (support.supported) {
    supportCheck.innerHTML = `
      <h2 class="support-ok">Passkey PRF supported</h2>
      <p>Platform authenticator: ${support.platformAuthenticator ? 'Yes' : 'No'}</p>
    `
    setupSection.classList.remove('hidden')
    loginSection.classList.remove('hidden')
    log('PRF support detected', 'success')
  } else {
    supportCheck.innerHTML = `
      <h2 class="support-warn">PRF not available</h2>
      <p>${support.reason || 'Your browser or authenticator does not support the PRF extension.'}</p>
      <p>Password fallback is available below.</p>
    `
    passwordSection.classList.remove('hidden')
    log(`PRF not supported: ${support.reason}`, 'error')
  }
}

// Setup: encrypt nsec with passkey
$('btn-setup').addEventListener('click', async () => {
  try {
    log('Starting passkey registration...')

    let nsecBytes: Uint8Array
    const existingNsec = ($('existing-nsec') as HTMLInputElement).value.trim()

    if (existingNsec) {
      nsecBytes = decodeNsec(existingNsec)
      log('Using existing nsec')
    } else {
      nsecBytes = generateNsec()
      log('Generated new nsec')
    }

    const npub = nsecToNpub(nsecBytes)
    log(`npub: ${npub}`)

    const rpId = window.location.hostname
    const { credential, prfOutput } = await registerPasskey({
      rpId,
      rpName: 'nostkey',
      userName: npub,
      userDisplayName: 'Nostr User',
    })

    log('Passkey registered with PRF', 'success')

    const encryptedBlob = encryptNsec({
      nsecBytes,
      prfOutput,
      credentialId: credential.credentialId,
    })

    // Zero out sensitive data
    prfOutput.fill(0)

    const eventTemplate = buildNostkeyEvent({
      credential,
      encryptedBlob,
      clientName: 'nostkey-demo',
    })

    // Show results
    $('result-npub').textContent = npub
    $('result-blob').textContent = encryptedBlob
    $('result-event').textContent = JSON.stringify(eventTemplate, null, 2)
    $('setup-result').classList.remove('hidden')

    log('nsec encrypted and event built', 'success')
    log('The encrypted blob is safe to publish to relays', 'info')

    // Copy button
    $('btn-copy-event').onclick = () => {
      navigator.clipboard.writeText(JSON.stringify(eventTemplate, null, 2))
      log('Event JSON copied to clipboard', 'success')
    }

    // Pre-fill login section for testing
    ;($('event-json') as HTMLTextAreaElement).value = JSON.stringify(eventTemplate, null, 2)
  } catch (err) {
    log(`Setup failed: ${(err as Error).message}`, 'error')
  }
})

// Login: decrypt nsec from event
$('btn-login').addEventListener('click', async () => {
  try {
    const eventJson = ($('event-json') as HTMLTextAreaElement).value.trim()
    if (!eventJson) {
      log('Paste an event JSON first', 'error')
      return
    }

    const event = JSON.parse(eventJson)
    const parsed = parseNostkeyEvent(event)

    log(`Decrypting with credential from ${parsed.rpId}...`)
    log('Authenticate with your passkey now...')

    const prfOutput = await authenticatePasskey({
      credentialId: parsed.credentialId,
      rpId: parsed.rpId,
      transports: parsed.transports as AuthenticatorTransport[],
    })

    const nsecBytes = decryptNsec({
      encryptedBlob: parsed.encryptedBlob,
      prfOutput,
      credentialId: parsed.credentialId,
    })

    // Zero out PRF output
    prfOutput.fill(0)

    const npub = nsecToNpub(nsecBytes)
    const nsec = encodeNsec(nsecBytes)

    // Zero out raw key
    nsecBytes.fill(0)

    $('login-npub').textContent = npub
    $('login-nsec').textContent = nsec
    $('login-result').classList.remove('hidden')

    log('nsec decrypted successfully!', 'success')
  } catch (err) {
    log(`Login failed: ${(err as Error).message}`, 'error')
  }
})

// Password fallback
$('btn-pw-encrypt').addEventListener('click', async () => {
  try {
    const nsec = ($('pw-nsec') as HTMLInputElement).value.trim()
    const password = ($('pw-password') as HTMLInputElement).value

    if (!nsec || !password) {
      log('Enter nsec and password', 'error')
      return
    }

    const nsecBytes = decodeNsec(nsec)
    log('Encrypting with password (this may take a moment)...')

    const encrypted = encryptNsecWithPassword(nsecBytes, password)
    nsecBytes.fill(0)

    $('pw-output').textContent = encrypted
    $('pw-result').classList.remove('hidden')
    log('Encrypted with password', 'success')
  } catch (err) {
    log(`Password encryption failed: ${(err as Error).message}`, 'error')
  }
})

$('btn-pw-decrypt').addEventListener('click', async () => {
  try {
    const blob = ($('pw-output') as HTMLElement).textContent?.trim()
    const password = ($('pw-password') as HTMLInputElement).value

    if (!blob || !password) {
      log('Encrypt something first and enter password', 'error')
      return
    }

    log('Decrypting with password...')
    const nsecBytes = decryptNsecFromPassword(blob, password)
    const nsec = encodeNsec(nsecBytes)
    nsecBytes.fill(0)

    $('pw-output').textContent = nsec
    log('Decrypted with password', 'success')
  } catch (err) {
    log(`Password decryption failed: ${(err as Error).message}`, 'error')
  }
})

init()
