// Production dependency wiring for the transactional email outbox worker.
import { randomUUID } from "node:crypto";
import { sendVerificationEmail } from "@/features/auth/lib/email/provider";
import { createVerificationToken } from "@/features/auth/server/verify/createToken";
import { env } from "@/lib/env";
import { createPrismaOutboxDb } from "./db";
import {
  buildInviteAcceptUrl,
  createInviteTokenDecryptor,
} from "./inviteCrypto";
import { sendInvitationEmail } from "./invitationEmail";
import type { OutboxProcessorDeps } from "./types";

function buildEnvInviteKeyring(): Map<number, string> {
  return new Map(Object.entries(env.INVITE_DELIVERY_ENCRYPTION_KEYS ?? {}).map(
    ([version, key]) => [Number(version), key],
  ));
}

export function createDefaultOutboxProcessorDeps(): OutboxProcessorDeps {
  const decryptInviteToken = createInviteTokenDecryptor(buildEnvInviteKeyring());
  return {
    db: createPrismaOutboxDb(),
    now: () => new Date(),
    generateClaimToken: randomUUID,
    createVerificationToken,
    sendVerificationEmail,
    decryptInviteToken,
    buildInviteAcceptUrl: (rawToken) =>
      buildInviteAcceptUrl(rawToken, env.APP_URL ?? env.NEXTAUTH_URL ?? env.AUTH_URL ?? "http://localhost:3000"),
    sendInvitationEmail,
  };
}
