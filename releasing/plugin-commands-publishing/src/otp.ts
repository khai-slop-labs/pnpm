import { PnpmError } from '@pnpm/error'
import { type ExportedManifest } from '@pnpm/exportable-manifest'
import { type PublishOptions } from 'libnpmpublish'
import qrcodeTerminal from 'qrcode-terminal'
import { SHARED_CONTEXT } from './oidc/utils/shared-context.js'

export interface OtpWebAuthFetchOptions {
  method: 'GET'
  retry?: {
    factor?: number
    maxTimeout?: number
    minTimeout?: number
    randomize?: boolean
    retries?: number
  }
  timeout?: number
}

export interface OtpWebAuthFetchResponse {
  readonly headers: {
    get: (name: string) => string | null
  }
  readonly json: (this: this) => Promise<unknown>
  readonly ok: boolean
  readonly status: number
}

export interface OtpPublishResponse {
  readonly ok: boolean
  readonly status: number
  readonly statusText: string
  readonly text: () => Promise<string>
}

export interface OtpEnquirer {
  prompt: (this: this, options: OtpEnquirerOptions) => Promise<OtpEnquirerResponse | undefined>
}

export interface OtpEnquirerOptions {
  message: string
  name: 'otp'
  type: 'input'
}

export interface OtpEnquirerResponse {
  otp?: string
}

export type OtpPublishFn = (
  manifest: ExportedManifest,
  tarballData: Buffer,
  options: PublishOptions
) => Promise<OtpPublishResponse>

export interface OtpDate {
  now: (this: this) => number
}

export interface OtpContext {
  Date: OtpDate
  setTimeout: (cb: () => void, ms: number) => void
  enquirer: OtpEnquirer
  fetch: (url: string, options: OtpWebAuthFetchOptions) => Promise<OtpWebAuthFetchResponse>
  globalInfo: (message: string) => void
  process: Record<'stdin' | 'stdout', { isTTY?: boolean }>
  publish: OtpPublishFn
}

export interface OtpParams {
  context?: OtpContext
  manifest: ExportedManifest
  publishOptions: PublishOptions
  tarballData: Buffer
}

export { SHARED_CONTEXT }

interface OtpErrorBody {
  authUrl?: string
  doneUrl?: string
}

interface OtpErrorHeaders {
  'npm-notice'?: string[]
  'www-authenticate'?: string[]
}

interface OtpError {
  body?: OtpErrorBody
  code: string
  headers?: OtpErrorHeaders
}

const isOtpError = (error: unknown): error is OtpError =>
  error != null &&
  typeof error === 'object' &&
  'code' in error &&
  error.code === 'EOTP'

/**
 * Regex to extract a URL from an npm-notice header message.
 *
 * npm-notice messages look like:
 *   "Open https://www.npmjs.com/login/ab12cd34-ef56 to use your security key for authentication"
 */
export const NPM_NOTICE_URL_RE = /https?:\/\/\S+/

/**
 * Regex to extract the login token from an npm login URL path.
 *
 * Matches URLs like `https://www.npmjs.com/login/ab12cd34-ef56-7890-abcd-ef1234567890`
 * and captures the hex-and-dash token segment.
 */
const LOGIN_TOKEN_RE = /\/login\/([a-f0-9]+(?:-[a-f0-9]+)*)(?:[/?#]|$)/i

/**
 * Publish a package, handling OTP challenges.
 *
 * Supports three authentication flows:
 * 1. **WebAuth flow** (body has `authUrl` + `doneUrl`): Opens a browser URL and polls `doneUrl` for a token.
 * 2. **npm-notice flow** (headers have `npm-notice` with a URL, no `authUrl`/`doneUrl`):
 *    Extracts the URL from the header, derives a poll URL from the registry, and polls for a token.
 * 3. **Classic OTP prompt**: Asks the user to type a one-time password.
 *
 * @throws {@link OtpWebAuthTimeoutError} if the webauth browser flow times out.
 * @throws {@link OtpNonInteractiveError} if OTP is required but the terminal is not interactive.
 * @throws {@link OtpSecondChallengeError} if the registry requests OTP a second time after one was submitted.
 * @throws the original error if OTP handling is not applicable.
 *
 * @see https://github.com/npm/cli/blob/7d900c46/lib/utils/otplease.js for npm's implementation.
 */
export async function publishWithOtpHandling ({
  context = SHARED_CONTEXT,
  manifest,
  publishOptions,
  tarballData,
}: OtpParams): Promise<OtpPublishResponse> {
  let response: OtpPublishResponse
  try {
    response = await context.publish(manifest, tarballData, publishOptions)
  } catch (error) {
    if (!isOtpError(error)) throw error
    if (!context.process.stdin.isTTY || !context.process.stdout.isTTY) {
      throw new OtpNonInteractiveError()
    }
    const fetchOptions: OtpWebAuthFetchOptions = {
      method: 'GET',
      retry: {
        factor: publishOptions.fetchRetryFactor,
        maxTimeout: publishOptions.fetchRetryMaxtimeout,
        minTimeout: publishOptions.fetchRetryMintimeout,
        retries: publishOptions.fetchRetries,
      },
      timeout: publishOptions.timeout,
    }
    let otp: string | undefined
    if (error.body?.authUrl && error.body?.doneUrl) {
      // Flow 1: WebAuth with explicit authUrl and doneUrl from the response body
      otp = await webAuthOtp(error.body.authUrl, error.body.doneUrl, context, fetchOptions)
    } else {
      // Check for npm-notice header containing a login URL (Flow 2)
      const npmNoticeUrl = extractNpmNoticeUrl(error.headers)
      const doneUrl = npmNoticeUrl ? derivePollUrl(npmNoticeUrl, publishOptions.registry) : undefined
      if (npmNoticeUrl && doneUrl) {
        // Flow 2: npm-notice header with login URL, derive poll URL
        logNpmNoticeMessages(error.headers, npmNoticeUrl, context)
        otp = await webAuthOtp(npmNoticeUrl, doneUrl, context, fetchOptions)
      } else {
        // Flow 3: Classic OTP prompt
        const enquirerResponse = await context.enquirer.prompt({
          message: 'This operation requires a one-time password.\nEnter OTP:',
          name: 'otp',
          type: 'input',
        })
        otp = enquirerResponse?.otp || undefined
      }
    }
    if (otp != null) {
      try {
        return await context.publish(manifest, tarballData, { ...publishOptions, otp })
      } catch (retryError) {
        if (isOtpError(retryError)) {
          throw new OtpSecondChallengeError()
        }
        throw retryError
      }
    }
    throw error
  }
  return response
}

/**
 * Extract a URL from the npm-notice headers array.
 */
function extractNpmNoticeUrl (headers?: OtpErrorHeaders): string | undefined {
  if (!headers?.['npm-notice']?.length) return undefined
  for (const notice of headers['npm-notice']) {
    const match = NPM_NOTICE_URL_RE.exec(notice)
    if (match) return match[0]
  }
  return undefined
}

/**
 * Derive the poll URL from the login URL and registry.
 *
 * npm's registry uses a pattern where the login URL is `https://www.npmjs.com/login/{token}`
 * and the poll URL is `{registry}/-/v1/login/poll/{token}`.
 *
 * @see https://github.com/nicolo-ribaudo/npm-profile/blob/main/lib/index.js for npm-profile's webAuthCheckLogin.
 */
function derivePollUrl (loginUrl: string, registry?: string): string | undefined {
  const tokenMatch = LOGIN_TOKEN_RE.exec(loginUrl)
  if (!tokenMatch) return undefined
  const token = tokenMatch[1]
  const baseUrl = (registry ?? 'https://registry.npmjs.org').replace(/\/$/, '')
  return `${baseUrl}/-/v1/login/poll/${token}`
}

/**
 * Log the npm-notice messages to the user along with a QR code for the login URL.
 */
function logNpmNoticeMessages (headers: OtpErrorHeaders | undefined, loginUrl: string, context: OtpContext): void {
  const notices = headers?.['npm-notice']
  if (notices?.length) {
    for (const notice of notices) {
      context.globalInfo(notice)
    }
  }
  const qrCode = generateQrCode(loginUrl)
  context.globalInfo(`\n${qrCode}`)
}

async function webAuthOtp (authUrl: string, doneUrl: string, context: OtpContext, fetchOptions: OtpWebAuthFetchOptions): Promise<string> {
  const qrCode = generateQrCode(authUrl)
  context.globalInfo(`Authenticate your account at:\n${authUrl}\n\n${qrCode}`)
  const startTime = context.Date.now()
  const timeout = 5 * 60 * 1000 // 5 minutes

  while (true) {
    if (context.Date.now() - startTime > timeout) {
      throw new OtpWebAuthTimeoutError(context.Date.now(), startTime, timeout)
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise<void>(resolve => context.setTimeout(resolve, 1000))
    let response: OtpWebAuthFetchResponse
    try {
      // eslint-disable-next-line no-await-in-loop
      response = await context.fetch(doneUrl, fetchOptions)
    } catch {
      continue
    }

    // npm's registry returns 200 when auth is complete, 202 when still pending
    if (response.status === 200) {
      let body: { token?: string }
      try {
        // eslint-disable-next-line no-await-in-loop
        body = await response.json() as { token?: string }
      } catch {
        continue
      }
      if (body.token) {
        return body.token
      }
    }

    if (response.status === 202) {
      // Respect Retry-After header if present
      const retryAfter = response.headers.get('retry-after')
      if (retryAfter) {
        const retryMs = Number(retryAfter) * 1000
        if (retryMs > 0) {
          // eslint-disable-next-line no-await-in-loop
          await new Promise<void>(resolve => context.setTimeout(resolve, retryMs))
        }
      }
      continue
    }

    if (!response.ok) continue
  }
}

function generateQrCode (url: string): string {
  let result = ''
  qrcodeTerminal.generate(url, { small: true }, (qr: string) => {
    result = qr
  })
  return result
}

export class OtpWebAuthTimeoutError extends PnpmError {
  readonly endTime: number
  readonly startTime: number
  readonly timeout: number
  constructor (endTime: number, startTime: number, timeout: number) {
    super('WEBAUTH_TIMEOUT', 'Web authentication timed out. Please try again.')
    this.endTime = endTime
    this.startTime = startTime
    this.timeout = timeout
  }
}

export class OtpNonInteractiveError extends PnpmError {
  constructor () {
    super('OTP_NON_INTERACTIVE', 'The registry requires a one-time password (OTP) but pnpm is not running in an interactive terminal. Please set the --otp option.')
  }
}

export class OtpSecondChallengeError extends PnpmError {
  constructor () {
    super('OTP_SECOND_CHALLENGE', 'The registry requested a one-time password (OTP) a second time after one was already provided. This is unexpected behavior from the registry.')
  }
}
