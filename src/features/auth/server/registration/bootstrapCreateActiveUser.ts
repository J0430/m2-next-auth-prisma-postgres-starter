// Creates explicit ACTIVE development seed identities behind two bootstrap guards.
import { env } from "@/lib/env";

type BootstrapRuntime = Readonly<{
  allowUserBootstrap: boolean;
  nodeEnv: string | undefined;
}>;

type BootstrapUserClient = Readonly<{
  user: Readonly<{
    upsert(input: {
      where: { email: string };
      update: Record<string, unknown>;
      create: Record<string, unknown>;
      select: { id: true; status: true };
    }): Promise<{ id: string; status: "ACTIVE" }>;
  }>;
}>;

type BootstrapCreateInput = Readonly<{
  client: BootstrapUserClient;
  email: string;
  name: string;
  passwordHash: string;
  profile?: Readonly<{ country: string; city: string; address: string }>;
}>;

function currentRuntime(): BootstrapRuntime {
  return {
    allowUserBootstrap: env.ALLOW_USER_BOOTSTRAP,
    nodeEnv: process.env.NODE_ENV,
  };
}

export async function bootstrapCreateActiveUser(
  input: BootstrapCreateInput,
): Promise<{ id: string; status: "ACTIVE" }> {
  const runtime = currentRuntime();
  if (!runtime.allowUserBootstrap || runtime.nodeEnv === "production") {
    throw new Error("USER_BOOTSTRAP_DISABLED");
  }
  const profile = input.profile
    ? { create: input.profile }
    : undefined;
  return input.client.user.upsert({
    where: { email: input.email.toLowerCase().trim() },
    update: {
      name: input.name,
      password: null,
      passwordHash: input.passwordHash,
      hasPasswordCredential: true,
      emailVerified: new Date(),
      status: "ACTIVE",
      role: "USER",
      origin: "FIRST_PARTY",
      ...(input.profile ? { profile: { upsert: { create: input.profile, update: input.profile } } } : {}),
    },
    create: {
      email: input.email.toLowerCase().trim(),
      name: input.name,
      password: null,
      passwordHash: input.passwordHash,
      hasPasswordCredential: true,
      emailVerified: new Date(),
      status: "ACTIVE",
      role: "USER",
      origin: "FIRST_PARTY",
      ...(profile ? { profile } : {}),
    },
    select: { id: true, status: true },
  });
}
