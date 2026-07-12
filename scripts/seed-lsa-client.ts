// Seed script: Register Learning Speaking App as an OAuth client
import crypto from "crypto";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";

const prisma = new PrismaClient();

const LSA_CLIENT = {
  name: "Learning Speaking App",
  description: "AI-powered speaking practice tool for English learners",
  redirectUris: [
    "http://localhost:3000/api/auth/callback/manumustudio",
    "http://localhost:3001/api/auth/callback/manumustudio",
  ],
  allowedOrigins: [
    "http://localhost:3000",
    "http://localhost:3001",
  ],
  scopes: ["openid", "email", "profile"],
};

const ClientSecretSchema = z.string().min(32);

async function main() {
  const clientSecret = ClientSecretSchema.parse(process.env.LSA_CLIENT_SECRET);
  const clientSecretHash = crypto
    .createHash("sha256")
    .update(clientSecret)
    .digest("hex");

  const record = await prisma.oAuthClient.create({
    data: {
      clientId: crypto.randomUUID(),
      clientSecretHash,
      name: LSA_CLIENT.name,
      description: LSA_CLIENT.description,
      redirectUris: LSA_CLIENT.redirectUris,
      allowedOrigins: LSA_CLIENT.allowedOrigins,
      scopes: LSA_CLIENT.scopes,
    },
    select: { clientId: true },
  });

  console.log("\n✅ OAuth client registered successfully!\n");
  console.log("Add this public identifier to your LSA project's .env.local:");
  console.log("─".repeat(50));
  console.log(`AUTH_CLIENT_ID=${record.clientId}`);
  console.log("─".repeat(50));
  console.log("\nThe pre-provisioned credential was hashed and was not emitted.\n");
}

main()
  .catch(() => {
    console.error("oauth_client_seed_failed", { code: "OAUTH_CLIENT_SEED_FAILED" });
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
