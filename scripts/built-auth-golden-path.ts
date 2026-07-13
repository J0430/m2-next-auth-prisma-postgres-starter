// Exercises credentials authentication through the downloaded Next.js build and disposable PostgreSQL.
import { createServer } from 'node:http';

import { PrismaClient } from '@prisma/client';
import { hash } from 'bcryptjs';
import { z } from 'zod';

const APP_ORIGIN = 'http://localhost:3000';
const RATE_LIMIT_PORT = 8079;
const PASSWORD = 'CI-only-password-42!';
const DISPOSABLE_DATABASE_NAME = 'auth_e2e';
const CsrfSchema = z.object({ csrfToken: z.string().min(1) });
const SessionSchema = z.object({
  user: z.object({ id: z.string().min(1), email: z.string().email() }),
});

function assertDisposableDatabaseUrl(rawDatabaseUrl: string | undefined): void {
  if (!rawDatabaseUrl) {
    throw new Error('DATABASE_URL must point to local disposable auth_e2e before running built-auth E2E');
  }
  const databaseUrl = new URL(rawDatabaseUrl);
  const databaseName = decodeURIComponent(databaseUrl.pathname.replace(/^\//u, ''));
  const isPostgres = databaseUrl.protocol === 'postgresql:' || databaseUrl.protocol === 'postgres:';
  const isLoopback = databaseUrl.hostname === 'localhost'
    || databaseUrl.hostname === '127.0.0.1'
    || databaseUrl.hostname === '[::1]';
  if (!isPostgres || !isLoopback || databaseName !== DISPOSABLE_DATABASE_NAME) {
    throw new Error(
      'Refusing to run built-auth E2E outside local disposable auth_e2e. '
      + 'Use DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_e2e with a local built app.',
    );
  }
}

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
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => { chunks.push(chunk); });
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const commandCount = countPipelineCommands(body);
      response.writeHead(200, { 'content-type': 'application/json' });
      if (request.url?.includes('/pipeline') || request.url?.includes('/multi-exec')) {
        response.end(JSON.stringify(Array.from({ length: commandCount }, rateLimitAllowedResult)));
        return;
      }
      response.end(JSON.stringify(rateLimitAllowedResult()));
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(RATE_LIMIT_PORT, '127.0.0.1', () => resolve(server));
  });
}

function countPipelineCommands(body: string): number {
  try {
    const parsed: unknown = JSON.parse(body);
    return Array.isArray(parsed) ? Math.max(1, parsed.length) : 1;
  } catch {
    return 1;
  }
}

function rateLimitAllowedResult(): { result: [number, number] } {
  return { result: [99, 100] };
}

assertDisposableDatabaseUrl(process.env.DATABASE_URL);
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
    throw new Error(
      `Credentials callback rejected the disposable database fixture: status=${callbackResponse.status} location=${location || '<missing>'}`,
    );
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
