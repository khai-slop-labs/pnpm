---
"@pnpm/plugin-commands-publishing": minor
"pnpm": minor
---

Added support for npm registry OTP and WebAuthn/passkey authentication flows during `pnpm publish`. When the registry responds with an OTP challenge, pnpm now handles three scenarios: (1) WebAuth flow with explicit `authUrl`/`doneUrl` in the response body, (2) npm-notice header containing a login URL (for passkey/security key flows), and (3) classic OTP prompt. For web-based flows, pnpm displays a QR code and polls the registry until authentication completes [#10591](https://github.com/pnpm/pnpm/issues/10591).
