// Creates audited INACTIVE identities after same-transaction admin MFA elevation.
import { z } from "zod";
import { requireAdminElevation } from "@/features/auth/server/adminElevation";
import type { AdminSession } from "@/features/auth/server/adminElevation";
import { prisma } from "@/lib/prisma";

const TrustedCreateInputSchema = z.object({
  email: z.string().trim().email().transform(value => value.toLowerCase()),
  name: z.string().trim().min(1).max(200).nullable(),
  reason: z.string().trim().min(3).max(500),
});

type TrustedCreateInput = Readonly<{
  session: AdminSession | null;
  email: string;
  name: string | null;
  reason: string;
}>;

export async function trustedCreateUser(
  input: TrustedCreateInput,
): Promise<{ id: string; status: "INACTIVE" }> {
  const parsed = TrustedCreateInputSchema.parse(input);
  return prisma.$transaction(async (tx) => {
    const context = { session: input.session, tx };
    const grant = await requireAdminElevation(context, "admin:user:create");
    const user = await tx.user.create({
      data: {
        email: parsed.email,
        name: parsed.name,
        status: "INACTIVE",
        emailVerified: null,
        password: null,
        passwordHash: null,
        hasPasswordCredential: false,
        origin: "FIRST_PARTY",
      },
      select: { id: true, status: true },
    });
    await tx.auditEvent.create({
      data: {
        actorUserId: grant.actorId,
        action: "admin.user.created",
        targetType: "User",
        targetId: user.id,
        targetUserId: user.id,
        metadata: { reason: parsed.reason, status: "INACTIVE", outcome: "SUCCESS" },
      },
    });
    return { id: user.id, status: "INACTIVE" };
  });
}
