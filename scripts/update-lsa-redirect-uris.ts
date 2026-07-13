// One-time script: Add localhost:3000 redirect URI to the existing LSA OAuth client
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

const CLIENT_ID = "c2056185-b1f3-450d-8caf-7883fd99eb71";

async function main() {
  const client = await prisma.oAuthClient.findUnique({
    where: { clientId: CLIENT_ID },
    select: { clientId: true, name: true, redirectUris: true, allowedOrigins: true },
  });

  if (!client) {
    console.error(`❌ OAuth client ${CLIENT_ID} not found`);
    process.exit(1);
  }

  console.log(`Found client: ${client.name}`);
  console.log(`Current redirectUris: ${JSON.stringify(client.redirectUris)}`);
  console.log(`Current allowedOrigins: ${JSON.stringify(client.allowedOrigins)}`);

  const newRedirectUris = Array.from(new Set([
    ...client.redirectUris,
    "http://localhost:3000/api/auth/callback/manumustudio",
  ]));

  const newAllowedOrigins = Array.from(new Set([
    ...client.allowedOrigins,
    "http://localhost:3000",
  ]));

  await prisma.oAuthClient.update({
    where: { clientId: CLIENT_ID },
    data: {
      redirectUris: newRedirectUris,
      allowedOrigins: newAllowedOrigins,
    },
  });

  console.log(`\n✅ Updated successfully!`);
  console.log(`New redirectUris: ${JSON.stringify(newRedirectUris)}`);
  console.log(`New allowedOrigins: ${JSON.stringify(newAllowedOrigins)}`);
}

main()
  .catch(() => {
    console.error("oauth_client_redirect_update_failed", {
      code: "OAUTH_CLIENT_REDIRECT_UPDATE_FAILED",
    });
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
