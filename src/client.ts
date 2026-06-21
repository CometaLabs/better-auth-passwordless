import type { BetterAuthClientPlugin } from "better-auth/client";
import type { passwordlessBundle } from "./server";

type PasswordlessBundleServer = typeof passwordlessBundle;

export const passwordlessBundleClient = () => {
  return {
    id: "passwordless-bundle",
    $InferServerPlugin: {} as ReturnType<PasswordlessBundleServer>,
  } satisfies BetterAuthClientPlugin;
};

