import type { BetterAuthPlugin } from "better-auth";
import { generateRandomString } from "better-auth/crypto";
import { parseUserInput, parseUserOutput } from "better-auth/db";
import { setSessionCookie } from "better-auth/cookies";
import { APIError, createAuthEndpoint, originCheck } from "better-auth/api";
import { createHash } from "crypto";
import * as z from "zod";

type SendEmailPayload = {
  to: string;
  otp: string;
  magicLinkUrl: string;
  expiresInSeconds: number;
  appName: string;
  requestMetadata?: Record<string, unknown>;
};

export type PasswordlessBundleOptions = {
  sendEmail: (payload: SendEmailPayload, ctx: unknown) => Promise<void> | void;
  expiresInSeconds?: number;
  otpLength?: number;
  allowedAttemptsOtp?: number;
  allowedAttemptsMagicLink?: number;
  disableSignUp?: boolean;
  rateLimit?: {
    windowSeconds?: number;
    max?: number;
  };
};

const requestBodySchema = z.object({
  email: z.email(),
  name: z.string().optional(),
  callbackURL: z.string().optional(),
  newUserCallbackURL: z.string().optional(),
  errorCallbackURL: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const verifyQuerySchema = z.object({
  token: z.string(),
  callbackURL: z.string().optional(),
  newUserCallbackURL: z.string().optional(),
  errorCallbackURL: z.string().optional(),
});

const verifyOtpBodySchema = z
  .object({
    email: z.email(),
    otp: z.string().min(1),
    name: z.string().optional(),
    image: z.string().optional(),
  })
  .and(z.record(z.string(), z.unknown()));

type VerificationTokenValue = {
  email: string;
  name?: string;
  attempt: number;
};

function getExpiresAt(expiresInSeconds: number) {
  return new Date(Date.now() + expiresInSeconds * 1000);
}

function generateOtp(length: number) {
  // Use cryptographically secure random string, then map to digits
  const random = generateRandomString(length * 2, "0-9");
  return random.slice(0, length);
}

function hashOtp(otp: string) {
  return createHash("sha256").update(otp).digest("hex");
}

function tokenIdentifier(token: string) {
  return `passwordless-bundle-token:${token}`;
}

function otpIdentifier(email: string) {
  return `passwordless-bundle-otp:sign-in:${email.toLowerCase()}`;
}

function pendingTokenIdentifier(email: string) {
  return `passwordless-bundle-pending-token:${email.toLowerCase()}`;
}

async function atomicVerifyOtp(
  ctx: any,
  opts: Required<Pick<PasswordlessBundleOptions, "allowedAttemptsOtp">>,
  identifier: string,
  providedOtp: string,
) {
  const verificationValue = await ctx.context.internalAdapter.findVerificationValue(identifier);
  if (!verificationValue) {
    throw APIError.fromStatus("BAD_REQUEST", { message: "INVALID_OTP" });
  }
  if (verificationValue.expiresAt < new Date()) {
    await ctx.context.internalAdapter.deleteVerificationByIdentifier(identifier);
    throw APIError.fromStatus("BAD_REQUEST", { message: "OTP_EXPIRED" });
  }

  const [storedHashedOtp, attemptsStr] = String(verificationValue.value).split(":");
  const attempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;

  if (attempts >= opts.allowedAttemptsOtp) {
    await ctx.context.internalAdapter.deleteVerificationByIdentifier(identifier);
    throw APIError.fromStatus("FORBIDDEN", { message: "TOO_MANY_ATTEMPTS" });
  }

  // delete-first to prevent concurrent reuse
  await ctx.context.internalAdapter.deleteVerificationByIdentifier(identifier);

  if (storedHashedOtp !== hashOtp(providedOtp)) {
    await ctx.context.internalAdapter.createVerificationValue({
      identifier,
      value: `${storedHashedOtp}:${attempts + 1}`,
      expiresAt: verificationValue.expiresAt,
    });
    throw APIError.fromStatus("BAD_REQUEST", { message: "INVALID_OTP" });
  }
}

export const passwordlessBundle = (options: PasswordlessBundleOptions) => {
  const expiresInSeconds = options.expiresInSeconds ?? 300;
  const otpLength = options.otpLength ?? 6;
  const allowedAttemptsOtp = options.allowedAttemptsOtp ?? 3;
  const allowedAttemptsMagicLink = options.allowedAttemptsMagicLink ?? 1;
  const disableSignUp = options.disableSignUp ?? false;
  const rateLimitWindowSeconds = options.rateLimit?.windowSeconds ?? 60;
  const rateLimitMax = options.rateLimit?.max ?? 5;

  return {
    id: "passwordless-bundle",
    endpoints: {
      request: createAuthEndpoint("/passwordless-bundle/request", {
        method: "POST",
        requireHeaders: true,
        body: requestBodySchema,
      }, async (ctx) => {
        const email = ctx.body.email.toLowerCase();

        // Invalidate any previous pending magic link token for this email
        const pendingId = pendingTokenIdentifier(email);
        const pendingRef = await ctx.context.internalAdapter.findVerificationValue(pendingId);
        if (pendingRef) {
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(
            tokenIdentifier(String(pendingRef.value)),
          );
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(pendingId);
        }

        const token = generateRandomString(32, "a-z", "A-Z");

        // Store a reference from email → token so we can invalidate it later
        await ctx.context.internalAdapter.createVerificationValue({
          identifier: pendingId,
          value: token,
          expiresAt: getExpiresAt(expiresInSeconds),
        });

        await ctx.context.internalAdapter.createVerificationValue({
          identifier: tokenIdentifier(token),
          value: JSON.stringify({
            email,
            name: ctx.body.name,
            attempt: 0,
          } satisfies VerificationTokenValue),
          expiresAt: getExpiresAt(expiresInSeconds),
        });

        const otp = generateOtp(otpLength);
        await ctx.context.internalAdapter
          .createVerificationValue({
            identifier: otpIdentifier(email),
            value: `${hashOtp(otp)}:0`,
            expiresAt: getExpiresAt(expiresInSeconds),
          })
          .catch(async () => {
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(otpIdentifier(email));
            await ctx.context.internalAdapter.createVerificationValue({
              identifier: otpIdentifier(email),
              value: `${hashOtp(otp)}:0`,
              expiresAt: getExpiresAt(expiresInSeconds),
            });
          });

        const realBaseURL = new URL(ctx.context.baseURL);
        const pathname = realBaseURL.pathname === "/" ? "" : realBaseURL.pathname;
        const basePath = pathname ? "" : ctx.context.options.basePath || "";
        const verifyUrl = new URL(
          `${pathname}${basePath}/passwordless-bundle/verify`,
          realBaseURL.origin,
        );
        verifyUrl.searchParams.set("token", token);
        verifyUrl.searchParams.set("callbackURL", ctx.body.callbackURL || "/");
        if (ctx.body.newUserCallbackURL) {
          verifyUrl.searchParams.set("newUserCallbackURL", ctx.body.newUserCallbackURL);
        }
        if (ctx.body.errorCallbackURL) {
          verifyUrl.searchParams.set("errorCallbackURL", ctx.body.errorCallbackURL);
        }

        const appName = ctx.context.options.appName ?? "Better Auth";
        await options.sendEmail(
          {
            to: email,
            otp,
            magicLinkUrl: verifyUrl.toString(),
            expiresInSeconds,
            appName,
            requestMetadata: ctx.body.metadata,
          },
          ctx,
        );

        // avoid user enumeration
        return ctx.json({ success: true });
      }),

      verify: createAuthEndpoint("/passwordless-bundle/verify", {
        method: "GET",
        query: verifyQuerySchema,
        requireHeaders: true,
        use: [
          originCheck((ctx: any) =>
            ctx.query.callbackURL ? decodeURIComponent(ctx.query.callbackURL) : "/",
          ),
          originCheck((ctx: any) =>
            ctx.query.newUserCallbackURL ? decodeURIComponent(ctx.query.newUserCallbackURL) : "/",
          ),
          originCheck((ctx: any) =>
            ctx.query.errorCallbackURL ? decodeURIComponent(ctx.query.errorCallbackURL) : "/",
          ),
        ],
      }, async (ctx) => {
        const token = ctx.query.token;

        const callbackURL = new URL(
          ctx.query.callbackURL ? decodeURIComponent(ctx.query.callbackURL) : "/",
          ctx.context.baseURL,
        ).toString();

        const errorCallbackURL = new URL(
          ctx.query.errorCallbackURL ? decodeURIComponent(ctx.query.errorCallbackURL) : callbackURL,
          ctx.context.baseURL,
        );

        function redirectWithError(error: string) {
          errorCallbackURL.searchParams.set("error", error);
          throw ctx.redirect(errorCallbackURL.toString());
        }

        const newUserCallbackURL = new URL(
          ctx.query.newUserCallbackURL
            ? decodeURIComponent(ctx.query.newUserCallbackURL)
            : callbackURL,
          ctx.context.baseURL,
        ).toString();

        const tokenValue = await ctx.context.internalAdapter.findVerificationValue(
          tokenIdentifier(token),
        );
        if (!tokenValue) {
          redirectWithError("INVALID_TOKEN");
          return ctx.json({ ok: false });
        }
        if (tokenValue.expiresAt < new Date()) {
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(tokenIdentifier(token));
          redirectWithError("EXPIRED_TOKEN");
        }

        const parsed = JSON.parse(String(tokenValue.value)) as VerificationTokenValue;
        const attempt = parsed.attempt ?? 0;
        if (attempt >= allowedAttemptsMagicLink) {
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(tokenIdentifier(token));
          redirectWithError("ATTEMPTS_EXCEEDED");
        }

        // delete-first to prevent concurrent reuse of the magic link
        await ctx.context.internalAdapter.deleteVerificationByIdentifier(tokenIdentifier(token));
        await ctx.context.internalAdapter.deleteVerificationByIdentifier(
          pendingTokenIdentifier(parsed.email),
        );

        let isNewUser = false;
        let user = await ctx.context.internalAdapter
          .findUserByEmail(parsed.email)
          .then((res: any) => res?.user);

        if (!user) {
          if (disableSignUp) {
            redirectWithError("new_user_signup_disabled");
            return ctx.json({ ok: false });
          }
          const newUser = await ctx.context.internalAdapter.createUser({
            email: parsed.email,
            emailVerified: true,
            name: parsed.name || "",
          });
          isNewUser = true;
          user = newUser;
          if (!user) redirectWithError("failed_to_create_user");
        }

        if (!user.emailVerified) {
          user = await ctx.context.internalAdapter.updateUser(user.id, { emailVerified: true });
        }

        const session = await ctx.context.internalAdapter.createSession(user.id);
        if (!session) redirectWithError("failed_to_create_session");

        await setSessionCookie(ctx, { session, user });

        if (!ctx.query.callbackURL) {
          return ctx.json({
            token: session.token,
            user: parseUserOutput(ctx.context.options, user),
          });
        }

        if (isNewUser) throw ctx.redirect(newUserCallbackURL);
        throw ctx.redirect(callbackURL);
      }),

      verifyOtp: createAuthEndpoint("/passwordless-bundle/verify-otp", {
        method: "POST",
        requireHeaders: true,
        body: verifyOtpBodySchema,
      }, async (ctx) => {
        const { email: rawEmail, otp, name, image, ...rest } = ctx.body;
        const email = rawEmail.toLowerCase();

        await atomicVerifyOtp(
          ctx,
          { allowedAttemptsOtp },
          otpIdentifier(email),
          otp,
        );

        // Invalidate the pending magic link token for this email since OTP succeeded
        const pendingRef = await ctx.context.internalAdapter.findVerificationValue(
          pendingTokenIdentifier(email),
        );
        if (pendingRef) {
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(
            tokenIdentifier(String(pendingRef.value)),
          );
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(
            pendingTokenIdentifier(email),
          );
        }

        let user = await ctx.context.internalAdapter
          .findUserByEmail(email)
          .then((res: any) => res?.user);

        if (!user) {
          if (disableSignUp) {
            throw APIError.fromStatus("BAD_REQUEST", { message: "INVALID_OTP" });
          }
          const additionalFields = parseUserInput(ctx.context.options, rest, "create");
          user = await ctx.context.internalAdapter.createUser({
            ...additionalFields,
            email,
            emailVerified: true,
            name: name || "",
            image,
          });
        } else if (!user.emailVerified) {
          user = await ctx.context.internalAdapter.updateUser(user.id, { emailVerified: true });
        }

        const session = await ctx.context.internalAdapter.createSession(user.id);
        await setSessionCookie(ctx, { session, user });

        return ctx.json({
          token: session.token,
          user: parseUserOutput(ctx.context.options, user),
        });
      }),
    },
    rateLimit: [
      {
        pathMatcher(path: string) {
          return (
            path === "/passwordless-bundle/request" ||
            path === "/passwordless-bundle/verify" ||
            path === "/passwordless-bundle/verify-otp"
          );
        },
        window: rateLimitWindowSeconds,
        max: rateLimitMax,
      },
    ],
    options,
  } satisfies BetterAuthPlugin;
};
