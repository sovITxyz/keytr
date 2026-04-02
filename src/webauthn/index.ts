export { checkPrfSupport, checkCapabilities, ensureBrowser } from './support.js'
export { registerPasskey } from './register.js'
export { registerKihPasskey } from './register-kih.js'
export { authenticatePasskey, discoverPasskey, unifiedDiscover } from './authenticate.js'
export { extractPrfOutput, isPrfEnabled } from './prf.js'
export { generateKihUserId, detectMode, extractKihKey } from './kih.js'
export { parseBackupFlags } from './flags.js'
export {
  signalUnknownCredential,
  signalAllAcceptedCredentialIds,
  signalCurrentUserDetails,
} from './signal.js'
