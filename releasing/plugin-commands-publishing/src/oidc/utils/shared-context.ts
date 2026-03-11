import ciInfo from 'ci-info'
import { fetch } from '@pnpm/fetch'
import { globalInfo } from '@pnpm/logger'
import enquirer from 'enquirer'
import { publish } from 'libnpmpublish'
import { type AuthTokenContext } from '../authToken.js'
import { type IdTokenContext } from '../idToken.js'
import { type ProvenanceContext } from '../provenance.js'
import { type OtpContext, type OtpEnquirer, type OtpPublishFn } from '../../otp.js'

type SharedContext =
& AuthTokenContext
& IdTokenContext
& ProvenanceContext
& OtpContext

export const SHARED_CONTEXT: SharedContext = {
  Date,
  ciInfo,
  enquirer: enquirer as unknown as OtpEnquirer,
  fetch,
  globalInfo,
  process,
  // @types/libnpmpublish unfortunately uses an outdated type definition of package.json
  publish: publish as unknown as OtpPublishFn,
  setTimeout,
}
