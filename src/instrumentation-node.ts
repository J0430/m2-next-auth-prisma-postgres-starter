// Runs database-backed startup invariants only in the production Node runtime.
import { runAdminMfaStartupReadiness } from "@/startup/adminMfaReadiness";

type ReadinessLoader = () => Promise<() => Promise<void>>;

const loadStoredKeyReadiness: ReadinessLoader = async () => {
  const [{ prisma }, { validateStoredAdminMfaKeyVersions }, { validateStoredInviteKeyVersions }, { env }] = await Promise.all([
    import("@/lib/prisma"),
    import("@/features/auth/server/adminMfa/secretCrypto"),
    import("@/features/auth/server/outbox/inviteCrypto"),
    import("@/lib/env"),
  ]);
  return async () => {
    await validateStoredAdminMfaKeyVersions(prisma);
    const keyring = new Map(Object.entries(env.INVITE_DELIVERY_ENCRYPTION_KEYS ?? {}).map(
      ([version, key]) => [Number(version), key],
    ));
    await validateStoredInviteKeyVersions(prisma, keyring);
  };
};

export async function registerAdminMfaInstrumentation(
  runtime: string | undefined,
  nodeEnv: string | undefined,
  loader: ReadinessLoader = loadStoredKeyReadiness,
): Promise<void> {
  await runAdminMfaStartupReadiness({
    runtime,
    nodeEnv,
    validate: async () => {
      const validate = await loader();
      await validate();
    },
  });
}
