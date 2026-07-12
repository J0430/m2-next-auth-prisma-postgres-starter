// Exercises credentials authentication through the downloaded Next.js build and disposable PostgreSQL.
import { createServer } from 'node:http';

import { PrismaClient } from '@prisma/client';
import { hash } from 'bcryptjs';
import { z } from 'zod';

const APP_ORIGIN = 'http://localhost:3000';
const RATE_LIMIT_PORT = 8079;
const PASSWORD = 'CI-only-password-42!';
const CsrfSchema = z.object({ csrfToken: z.string().min(1) });
const SessionSchema = z.object({
  user: z.object({ id: z.string().min(1), email: z.string().email() }),
});

function cookiesFrom(response: Response): string[] {
  const header = response.headers.get('set-cookie') ?? '';
  return [...header.matchAll(/((?:__Secure-|__Host-)?next-auth\.[^=;, ]+=[^;,]*)/g)]
    .map((match) => match[1])
    .filter((cookie): cookie is string => cookie !== undefined);
}

function mergeCookies(...groups: string[][]): string {
  const cookies = new Map<string, string>();
  for (const cookie of groups.flat()) {
    cookies.set(cookie.slice(0, cookie.indexOf('=')), cookie);
  }
  return [...cookies.values()].join('; ');
}

function startRateLimitStub(): Promise<ReturnType<typeof createServer>> {
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ result: [99, 100] }));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(RATE_LIMIT_PORT, '127.0.0.1', () => resolve(server));
  });
}

const prisma = new PrismaClient();
const email = `ci-auth-golden-${Date.now()}@example.invalid`;
const rateLimitStub = await startRateLimitStub();

try {
  await prisma.user.create({
    data: {
      email,
      emailVerified: new Date(),
      passwordHash: await hash(PASSWORD, 10),
      hasPasswordCredential: true,
      status: 'ACTIVE',
      origin: 'FIRST_PARTY',
    },
  });

  const csrfResponse = await fetch(`${APP_ORIGIN}/api/auth/csrf`);
  if (!csrfResponse.ok) throw new Error(`CSRF endpoint returned HTTP ${csrfResponse.status}`);
  const { csrfToken } = CsrfSchema.parse(await csrfResponse.json());
  const csrfCookies = cookiesFrom(csrfResponse);
  if (csrfCookies.length === 0) throw new Error('CSRF endpoint did not set an auth cookie');

  const callbackResponse = await fetch(`${APP_ORIGIN}/api/auth/callback/credentials`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: mergeCookies(csrfCookies),
    },
    body: new URLSearchParams({ csrfToken, email, password: PASSWORD, callbackUrl: APP_ORIGIN }),
  });
  if (callbackResponse.status !== 302) {
    throw new Error(`Credentials callback returned HTTP ${callbackResponse.status}`);
  }
  const location = callbackResponse.headers.get('location') ?? '';
  if (location.includes('/api/auth/error') || location.includes('error=')) {
    throw new Error('Credentials callback rejected the disposable database fixture');
  }

  const sessionCookies = cookiesFrom(callbackResponse);
  if (sessionCookies.length === 0) throw new Error('Credentials callback did not issue a session cookie');
  const sessionResponse = await fetch(`${APP_ORIGIN}/api/auth/session`, {
    headers: { cookie: mergeCookies(csrfCookies, sessionCookies) },
  });
  if (!sessionResponse.ok) throw new Error(`Session endpoint returned HTTP ${sessionResponse.status}`);
  const session = SessionSchema.parse(await sessionResponse.json());
  if (session.user.email !== email) throw new Error('Authenticated session does not match the fixture');
} finally {
  await prisma.user.deleteMany({ where: { email } });
  await prisma.$disconnect();
  rateLimitStub.close();
}
