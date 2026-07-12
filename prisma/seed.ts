// prisma/seed.ts — development-only database seed. Refuses to run in production.
import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { hashClientSecret } from '../src/features/auth/server/oauth/clientRegistry';
import { bootstrapCreateActiveUser } from '../src/features/auth/server/registration/bootstrapCreateActiveUser';

// ─── Safety guards (run before any Prisma construction) ──────────────────────

if (process.env.NODE_ENV === 'production') {
  console.error('[seed] Refused: NODE_ENV is production.');
  process.exit(1);
}

if (process.env.SEED_CONFIRMATION !== 'DEVELOPMENT_ONLY') {
  console.error('[seed] Refused: set SEED_CONFIRMATION=DEVELOPMENT_ONLY to proceed.');
  process.exit(1);
}

const primaryDemoPassword = process.env.SEED_ADMIN_PASSWORD;
const userPassword = process.env.SEED_USER_PASSWORD;
const oauthClientSecret = process.env.SEED_OAUTH_CLIENT_SECRET;

if (!primaryDemoPassword || primaryDemoPassword.length < 16) {
  console.error('[seed] Refused: SEED_ADMIN_PASSWORD (legacy name) must be at least 16 characters.');
  process.exit(1);
}

if (!userPassword || userPassword.length < 16) {
  console.error('[seed] Refused: SEED_USER_PASSWORD must be at least 16 characters.');
  process.exit(1);
}

if (!oauthClientSecret || oauthClientSecret.length < 32) {
  console.error('[seed] Refused: SEED_OAUTH_CLIENT_SECRET must be at least 32 characters.');
  process.exit(1);
}

// ─── Seed ────────────────────────────────────────────────────────────────────

const prisma = new PrismaClient();

async function main() {
  const primaryDemoPassHash = await bcrypt.hash(primaryDemoPassword, 10);
  const userPassHash = await bcrypt.hash(userPassword, 10);

  await bootstrapCreateActiveUser({
    client: prisma,
    email: 'admin@demo.io',
    name: 'Admin Demo',
    passwordHash: primaryDemoPassHash,
    profile: { country: 'GB', city: 'London', address: '221B Baker Street' },
  });
  console.log('[seed] Created/updated non-admin demo user: admin@demo.io');

  await bootstrapCreateActiveUser({
    client: prisma,
    email: 'user@demo.io',
    name: 'User Demo',
    passwordHash: userPassHash,
    profile: { country: 'US', city: 'Miami', address: '1 Ocean Dr' },
  });
  console.log('[seed] Created/updated user: user@demo.io');

  const petsgramClientId = 'petsgram-web';
  const existingClient = await prisma.oAuthClient.findUnique({
    where: { clientId: petsgramClientId },
    select: { clientId: true },
  });

  if (!existingClient) {
    await prisma.oAuthClient.create({
      data: {
        clientId: petsgramClientId,
        clientSecretHash: hashClientSecret(oauthClientSecret),
        name: 'Petsgram Web',
        description: 'Petsgram frontend application',
        redirectUris: ['http://localhost:5173/auth/callback'],
        allowedOrigins: ['http://localhost:5173'],
        scopes: ['openid', 'email', 'profile'],
      },
    });
    console.log(`[seed] Created OAuth client: ${petsgramClientId}`);
  } else {
    console.log(`[seed] OAuth client already exists: ${petsgramClientId}`);
  }

  console.log('[seed] Done.');
}

main()
  .catch((e: unknown) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
