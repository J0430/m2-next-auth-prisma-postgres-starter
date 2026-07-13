// Fails release readiness when stored MFA factors reference unavailable key versions.
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { validateStoredAdminMfaKeyVersions } from "../src/features/auth/server/adminMfa/secretCrypto";

const prisma = new PrismaClient();

try {
  await validateStoredAdminMfaKeyVersions(prisma);
} finally {
  await prisma.$disconnect();
}
