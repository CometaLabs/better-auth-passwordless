# @cometalabs/better-auth-passwordless

Passwordless authentication plugin for [Better Auth](https://better-auth.com). Enables OTP codes and magic links via email — no password required.

## Installation

```bash
npm install @cometalabs/better-auth-passwordless
# or
pnpm add @cometalabs/better-auth-passwordless
```

## Usage

```ts
import { betterAuth } from "better-auth";
import { passwordlessPlugin } from "@cometalabs/better-auth-passwordless";

export const auth = betterAuth({
  plugins: [
    passwordlessPlugin({
      // options
    }),
  ],
});
```

## How it works

1. User enters their email
2. Plugin sends an email with an OTP code **and** a magic link
3. User either enters the code or clicks the link — both complete authentication

## License

MIT © [Cometalabs](https://cometalabs.io)
