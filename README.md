<a href="https://cometalabs.io">
  <picture>
    <source srcset="https://cometalabs-assets.s3.us-east-1.amazonaws.com/better-auth-passwordless/assets/cometa-banner.png" />
    <img alt="Cometa" src="https://cometalabs-assets.s3.us-east-1.amazonaws.com/better-auth-passwordless/assets/cometa-banner.png" />
  </picture>
</a>

<br />

# 🔐 better-auth-passwordless

**better-auth-passwordless** is a passwordless authentication plugin for [Better Auth](https://better-auth.com). It enables login without passwords by sending users a **one-time code (OTP)** and/or a **magic link** via email — just like Slack or Linear do it.

## Features

- 🔑 Passwordless login via OTP code or magic link
- 📧 Single email with both an OTP and a clickable deep link
- 🔒 Atomic OTP verification to prevent concurrent reuse
- 🚦 Built-in rate limiting per endpoint
- 🛡️ Configurable max attempts for both OTP and magic link
- 🚫 Optional sign-up disable (existing users only)
- 📦 Full TypeScript support with exported types
- ⚡️ Works seamlessly as a Better Auth plugin

## Installation

### npm
```bash
npm install @cometalabs/better-auth-passwordless
```

### pnpm
```bash
pnpm add @cometalabs/better-auth-passwordless
```

### bun
```bash
bun add @cometalabs/better-auth-passwordless
```

> Requires `better-auth >= 1.0.0` and `zod >= 4.0.0`

## How it works

1. User enters their email address
2. Plugin creates a signed token and an OTP, stores them in the verification table
3. Your `sendEmail` function is called with both the OTP and a magic link URL
4. User either:
   - **Clicks the magic link** → instantly authenticated via `GET /passwordless-bundle/verify`
   - **Enters the OTP code** → authenticated via `POST /passwordless-bundle/verify-otp`
5. On success, a session is created and the user is redirected or receives a session token

## Usage

### Server setup

```ts
import { betterAuth } from "better-auth";
import { passwordlessBundle } from "@cometalabs/better-auth-passwordless";
// or from the server subpath:
// import { passwordlessBundle } from "@cometalabs/better-auth-passwordless/server";

export const auth = betterAuth({
  plugins: [
    passwordlessBundle({
      sendEmail: async ({ to, otp, magicLinkUrl, expiresInSeconds, appName }) => {
        // Send your email here using Resend, Nodemailer, etc.
        await resend.emails.send({
          from: "noreply@yourapp.com",
          to,
          subject: `Your ${appName} login code`,
          html: `
            <p>Your login code is: <strong>${otp}</strong></p>
            <p>Or <a href="${magicLinkUrl}">click here</a> to log in directly.</p>
            <p>Expires in ${expiresInSeconds / 60} minutes.</p>
          `,
        });
      },
    }),
  ],
});
```

### Client setup

```ts
import { createAuthClient } from "better-auth/client";
import { passwordlessBundleClient } from "@cometalabs/better-auth-passwordless";
// or from the client subpath:
// import { passwordlessBundleClient } from "@cometalabs/better-auth-passwordless/client";

export const authClient = createAuthClient({
  plugins: [passwordlessBundleClient()],
});
```

### Requesting a login email

```ts
await authClient.passwordlessBundle.request({
  email: "user@example.com",
  callbackURL: "/dashboard",         // redirect after magic link login
  newUserCallbackURL: "/onboarding", // redirect for first-time users (optional)
  errorCallbackURL: "/login?error",  // redirect on error (optional)
});
```

### Verifying with OTP

```ts
await authClient.passwordlessBundle.verifyOtp({
  email: "user@example.com",
  otp: "123456",
});
```

## Configuration options

```ts
passwordlessBundle({
  sendEmail: async (payload, ctx) => { /* required */ },

  expiresInSeconds: 300,       // Token/OTP expiry in seconds (default: 300 = 5 min)
  otpLength: 6,                // Length of the OTP code (default: 6)
  allowedAttemptsOtp: 3,       // Max OTP verification attempts (default: 3)
  allowedAttemptsMagicLink: 1, // Max magic link uses (default: 1)
  disableSignUp: false,        // Block new user creation (default: false)

  rateLimit: {
    windowSeconds: 60,         // Rate limit window (default: 60s)
    max: 5,                    // Max requests per window (default: 5)
  },
})
```

### `sendEmail` payload

| Field | Type | Description |
|-------|------|-------------|
| `to` | `string` | Recipient email address |
| `otp` | `string` | The one-time code to display |
| `magicLinkUrl` | `string` | The full URL for the magic link |
| `expiresInSeconds` | `number` | Seconds until both expire |
| `appName` | `string` | Value from `betterAuth({ appName })` |
| `requestMetadata` | `Record<string, unknown> \| undefined` | Extra data passed in the request body |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/passwordless-bundle/request` | Send OTP + magic link email |
| `GET` | `/passwordless-bundle/verify` | Verify magic link token (redirects) |
| `POST` | `/passwordless-bundle/verify-otp` | Verify OTP code |

## Cometa Labs

better-auth-passwordless is built with ☄️ by [Cometa Labs](https://cometalabs.io).

Source code: [github.com/CometaLabs/better-auth-passwordless](https://github.com/CometaLabs/better-auth-passwordless)

## Authors

- [Alexei Soliz](https://github.com/emprecario)

## License

MIT - © 2025 Cometa Labs

