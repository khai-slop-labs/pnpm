import { jest } from '@jest/globals'
import { type PublishOptions } from 'libnpmpublish'
import {
  type OtpContext,
  type OtpPublishResponse,
  type OtpWebAuthFetchResponse,
  NPM_NOTICE_URL_RE,
  OtpNonInteractiveError,
  OtpSecondChallengeError,
  OtpWebAuthTimeoutError,
  publishWithOtpHandling,
} from '../src/otp.js'

function createOtpError (overrides?: {
  body?: { authUrl?: string; doneUrl?: string }
  headers?: Record<string, string[]>
}): Error & { code: string; body?: unknown; headers?: unknown } {
  const err = Object.assign(new Error('OTP required for authentication'), {
    code: 'EOTP',
    body: overrides?.body,
    headers: overrides?.headers,
  })
  return err
}

function createMockContext (overrides?: Partial<OtpContext>): OtpContext {
  return {
    Date: { now: jest.fn(() => 0) },
    setTimeout: jest.fn((cb: () => void) => cb()),
    enquirer: { prompt: jest.fn(async () => ({ otp: '123456' })) },
    fetch: jest.fn(async () => ({
      headers: { get: () => null },
      json: async () => ({}),
      ok: false,
      status: 404,
    })),
    globalInfo: jest.fn(),
    process: { stdin: { isTTY: true }, stdout: { isTTY: true } },
    publish: jest.fn(async () => ({ ok: true, status: 200, statusText: 'OK', text: async () => '' })),
    ...overrides,
  }
}

const defaultManifest = { name: '@test/pkg', version: '1.0.0' }
const defaultTarball = Buffer.from('test-tarball')
const defaultPublishOptions = { registry: 'https://registry.npmjs.org/' }

describe('NPM_NOTICE_URL_RE', () => {
  test('extracts URL from npm-notice message', () => {
    const message = 'Open https://www.npmjs.com/login/ab12cd34-ef56-7890-abcd-ef1234567890 to use your security key for authentication'
    const match = NPM_NOTICE_URL_RE.exec(message)
    expect(match).not.toBeNull()
    expect(match![0]).toBe('https://www.npmjs.com/login/ab12cd34-ef56-7890-abcd-ef1234567890')
  })

  test('extracts URL with http scheme', () => {
    const message = 'Open http://localhost:4873/login/abc123 for auth'
    const match = NPM_NOTICE_URL_RE.exec(message)
    expect(match).not.toBeNull()
    expect(match![0]).toBe('http://localhost:4873/login/abc123')
  })

  test('returns null when no URL present', () => {
    const message = 'You must provide a one-time pass.'
    const match = NPM_NOTICE_URL_RE.exec(message)
    expect(match).toBeNull()
  })
})

describe('publishWithOtpHandling', () => {
  test('returns response directly when publish succeeds without OTP challenge', async () => {
    const expectedResponse: OtpPublishResponse = { ok: true, status: 200, statusText: 'OK', text: async () => '' }
    const context = createMockContext({
      publish: jest.fn(async () => expectedResponse),
    })

    const result = await publishWithOtpHandling({
      context,
      manifest: defaultManifest,
      publishOptions: defaultPublishOptions,
      tarballData: defaultTarball,
    })

    expect(result).toBe(expectedResponse)
    expect(context.publish).toHaveBeenCalledTimes(1)
  })

  test('throws non-OTP errors directly', async () => {
    const nonOtpError = Object.assign(new Error('forbidden'), { code: 'E403' })
    const context = createMockContext({
      publish: jest.fn(async () => { throw nonOtpError }),
    })

    await expect(publishWithOtpHandling({
      context,
      manifest: defaultManifest,
      publishOptions: defaultPublishOptions,
      tarballData: defaultTarball,
    })).rejects.toThrow('forbidden')
  })

  test('throws OtpNonInteractiveError when not a TTY', async () => {
    const context = createMockContext({
      process: { stdin: { isTTY: false }, stdout: { isTTY: true } },
      publish: jest.fn(async () => { throw createOtpError() }),
    })

    await expect(publishWithOtpHandling({
      context,
      manifest: defaultManifest,
      publishOptions: defaultPublishOptions,
      tarballData: defaultTarball,
    })).rejects.toThrow(OtpNonInteractiveError)
  })

  describe('Flow 1: WebAuth with authUrl and doneUrl', () => {
    test('polls doneUrl and retries publish with token', async () => {
      let callCount = 0
      const context = createMockContext({
        publish: jest.fn(async (_m: unknown, _t: unknown, opts: PublishOptions) => {
          if (!opts.otp) {
            throw createOtpError({
              body: {
                authUrl: 'https://www.npmjs.com/login/abc123',
                doneUrl: 'https://registry.npmjs.org/-/v1/login/poll/abc123',
              },
            })
          }
          return { ok: true, status: 200, statusText: 'OK', text: async () => '' }
        }),
        fetch: jest.fn(async () => {
          callCount++
          if (callCount < 3) {
            return {
              headers: { get: () => null },
              json: async () => ({}),
              ok: false,
              status: 202,
            } as OtpWebAuthFetchResponse
          }
          return {
            headers: { get: () => null },
            json: async () => ({ token: 'web-auth-token' }),
            ok: true,
            status: 200,
          } as OtpWebAuthFetchResponse
        }),
      })

      const result = await publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })

      expect(result.ok).toBe(true)
      expect(context.publish).toHaveBeenCalledTimes(2)
      expect(context.publish).toHaveBeenLastCalledWith(
        defaultManifest,
        defaultTarball,
        expect.objectContaining({ otp: 'web-auth-token' })
      )
      expect(context.globalInfo).toHaveBeenCalled()
    })
  })

  describe('Flow 2: npm-notice header with login URL', () => {
    test('extracts URL from npm-notice, derives poll URL, and polls for token', async () => {
      let fetchCallCount = 0
      const context = createMockContext({
        publish: jest.fn(async (_m: unknown, _t: unknown, opts: PublishOptions) => {
          if (!opts.otp) {
            throw createOtpError({
              headers: {
                'www-authenticate': ['OTP'],
                'npm-notice': ['Open https://www.npmjs.com/login/ab12cd34-ef56-7890-abcd-ef1234567890 to use your security key for authentication'],
              },
            })
          }
          return { ok: true, status: 200, statusText: 'OK', text: async () => '' }
        }),
        fetch: jest.fn(async (url) => {
          expect(url).toBe('https://registry.npmjs.org/-/v1/login/poll/ab12cd34-ef56-7890-abcd-ef1234567890')
          fetchCallCount++
          if (fetchCallCount < 2) {
            return {
              headers: { get: () => '1' },
              json: async () => ({}),
              ok: true,
              status: 202,
            } as OtpWebAuthFetchResponse
          }
          return {
            headers: { get: () => null },
            json: async () => ({ token: 'passkey-token' }),
            ok: true,
            status: 200,
          } as OtpWebAuthFetchResponse
        }),
      })

      const result = await publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: { registry: 'https://registry.npmjs.org/' },
        tarballData: defaultTarball,
      })

      expect(result.ok).toBe(true)
      expect(context.publish).toHaveBeenCalledTimes(2)
      expect(context.publish).toHaveBeenLastCalledWith(
        defaultManifest,
        defaultTarball,
        expect.objectContaining({ otp: 'passkey-token' })
      )
      // Should log npm-notice messages
      expect(context.globalInfo).toHaveBeenCalled()
    })

    test('uses registry from publishOptions to construct poll URL', async () => {
      const context = createMockContext({
        publish: jest.fn(async (_m: unknown, _t: unknown, opts: PublishOptions) => {
          if (!opts.otp) {
            throw createOtpError({
              headers: {
                'npm-notice': ['Open https://custom.registry.com/login/abc123 to auth'],
              },
            })
          }
          return { ok: true, status: 200, statusText: 'OK', text: async () => '' }
        }),
        fetch: jest.fn(async (url) => {
          expect(url).toBe('https://custom.registry.com/-/v1/login/poll/abc123')
          return {
            headers: { get: () => null },
            json: async () => ({ token: 'custom-token' }),
            ok: true,
            status: 200,
          } as OtpWebAuthFetchResponse
        }),
      })

      const result = await publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: { registry: 'https://custom.registry.com/' },
        tarballData: defaultTarball,
      })

      expect(result.ok).toBe(true)
    })
  })

  describe('Flow 3: Classic OTP prompt', () => {
    test('prompts for OTP when no authUrl/doneUrl and no npm-notice URL', async () => {
      const context = createMockContext({
        enquirer: { prompt: jest.fn(async () => ({ otp: '654321' })) },
        publish: jest.fn(async (_m: unknown, _t: unknown, opts: PublishOptions) => {
          if (!opts.otp) {
            throw createOtpError()
          }
          return { ok: true, status: 200, statusText: 'OK', text: async () => '' }
        }),
      })

      const result = await publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })

      expect(result.ok).toBe(true)
      expect(context.enquirer.prompt).toHaveBeenCalledWith({
        message: 'This operation requires a one-time password.\nEnter OTP:',
        name: 'otp',
        type: 'input',
      })
      expect(context.publish).toHaveBeenLastCalledWith(
        defaultManifest,
        defaultTarball,
        expect.objectContaining({ otp: '654321' })
      )
    })

    test('falls back to classic OTP when npm-notice has no URL', async () => {
      const context = createMockContext({
        enquirer: { prompt: jest.fn(async () => ({ otp: '111111' })) },
        publish: jest.fn(async (_m: unknown, _t: unknown, opts: PublishOptions) => {
          if (!opts.otp) {
            throw createOtpError({
              headers: {
                'npm-notice': ['You must provide a one-time pass.'],
              },
            })
          }
          return { ok: true, status: 200, statusText: 'OK', text: async () => '' }
        }),
      })

      const result = await publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })

      expect(result.ok).toBe(true)
      expect(context.enquirer.prompt).toHaveBeenCalled()
    })
  })

  describe('timeout handling', () => {
    test('throws OtpWebAuthTimeoutError when polling exceeds 5 minutes', async () => {
      let time = 0
      const context = createMockContext({
        Date: { now: jest.fn(() => time) },
        setTimeout: jest.fn((cb: () => void) => {
          time += 6 * 60 * 1000 // Jump past 5-minute timeout
          cb()
        }),
        publish: jest.fn(async () => {
          throw createOtpError({
            body: {
              authUrl: 'https://www.npmjs.com/login/abc',
              doneUrl: 'https://registry.npmjs.org/-/v1/login/poll/abc',
            },
          })
        }),
        fetch: jest.fn(async () => ({
          headers: { get: () => null },
          json: async () => ({}),
          ok: false,
          status: 202,
        })),
      })

      await expect(publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })).rejects.toThrow(OtpWebAuthTimeoutError)
    })
  })

  describe('retry error handling', () => {
    test('throws OtpSecondChallengeError when OTP is rejected with another EOTP', async () => {
      const context = createMockContext({
        enquirer: { prompt: jest.fn(async () => ({ otp: '123456' })) },
        publish: jest.fn(async () => { throw createOtpError() }),
      })

      await expect(publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })).rejects.toThrow(OtpSecondChallengeError)
    })

    test('throws non-OTP errors from retry attempt', async () => {
      let callCount = 0
      const context = createMockContext({
        enquirer: { prompt: jest.fn(async () => ({ otp: '123456' })) },
        publish: jest.fn(async () => {
          callCount++
          if (callCount === 1) throw createOtpError()
          throw Object.assign(new Error('server error'), { code: 'E500' })
        }),
      })

      await expect(publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })).rejects.toThrow('server error')
    })
  })

  describe('Retry-After header', () => {
    test('respects Retry-After header on 202 responses', async () => {
      let fetchCallCount = 0
      const setTimeoutCalls: number[] = []
      const context = createMockContext({
        setTimeout: jest.fn((cb: () => void, ms: number) => {
          setTimeoutCalls.push(ms)
          cb()
        }),
        publish: jest.fn(async (_m: unknown, _t: unknown, opts: PublishOptions) => {
          if (!opts.otp) {
            throw createOtpError({
              body: {
                authUrl: 'https://www.npmjs.com/login/abc',
                doneUrl: 'https://registry.npmjs.org/-/v1/login/poll/abc',
              },
            })
          }
          return { ok: true, status: 200, statusText: 'OK', text: async () => '' }
        }),
        fetch: jest.fn(async () => {
          fetchCallCount++
          if (fetchCallCount < 3) {
            return {
              headers: { get: (name: string) => name === 'retry-after' ? '5' : null },
              json: async () => ({}),
              ok: true,
              status: 202,
            } as OtpWebAuthFetchResponse
          }
          return {
            headers: { get: () => null },
            json: async () => ({ token: 'token-after-retry' }),
            ok: true,
            status: 200,
          } as OtpWebAuthFetchResponse
        }),
      })

      await publishWithOtpHandling({
        context,
        manifest: defaultManifest,
        publishOptions: defaultPublishOptions,
        tarballData: defaultTarball,
      })

      // Should have waited with Retry-After value (5 seconds = 5000ms)
      expect(setTimeoutCalls).toContain(5000)
    })
  })
})
