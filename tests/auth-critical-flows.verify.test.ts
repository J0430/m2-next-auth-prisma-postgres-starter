// Tests for OTP email verification: token creation, consumption, attempt limits, and resend
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';

const ORIGINAL_ENV = { ...process.env };

vi.mock('@/lib/prisma', () => ({
  prisma: {
    verificationToken: {
      upsert: vi.fn(),
      create: vi.fn(),
      findFirst: vi.fn(),
      update: vi.fn(),
      deleteMany: vi.fn(),
    },
    user: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    $transaction: vi.fn(),
  },
}));

vi.mock('@/features/auth/lib/email/provider', () => ({
  sendVerificationEmail: vi.fn(),
}));

vi.mock('crypto', () => ({
  default: {
    randomInt: vi.fn(() => 123456),
    createHash: vi.fn(() => {
      let value = '';
      const hashApi = {
        update: vi.fn((input: string) => {
          value = input;
          return hashApi;
        }),
        digest: vi.fn(() => `hash:${value}`),
      };
      return {
        ...hashApi,
      };
    }),
    // HMAC stub: produces deterministic "hmac:<code>" for test assertions
    createHmac: vi.fn((_algo: string, _key: string) => {
      let value = '';
      const hmacApi = {
        update: vi.fn((input: string) => {
          value = input;
          return hmacApi;
        }),
        digest: vi.fn(() => `hmac:${value}`),
      };
      return hmacApi;
    }),
  },
}));

const NOW = new Date('2024-01-01T00:00:00Z');

beforeEach(() => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  process.env.SKIP_ENV_VALIDATION = 'true';
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://localhost/test';
  process.env.NEXTAUTH_SECRET = process.env.NEXTAUTH_SECRET ?? 'x'.repeat(32);
  process.env.VERIFY_TOKEN_TTL_MINUTES = '10';
  process.env.VERIFY_RESEND_COOLDOWN_MINUTES = '2';
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
  Object.keys(process.env).forEach((key) => {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  });
  Object.assign(process.env, ORIGINAL_ENV);
});

describe('OTP verification tokens', () => {
  it('creates hashed OTP token and returns plaintext code', async () => {
    const { createVerificationToken } = await import('@/features/auth/server/verify/createToken');
    const { prisma } = await import('@/lib/prisma');
    const prismaMock = prisma as unknown as {
      $transaction: Mock;
      verificationToken: { upsert: Mock };
    };

    prismaMock.verificationToken.upsert.mockResolvedValue({});

    const result = await createVerificationToken('User@Example.com');

    expect(prismaMock.verificationToken.upsert).toHaveBeenCalledWith({
      where: { identifier: 'user@example.com' },
      create: {
        identifier: 'user@example.com',
        token: 'hmac:123456',
        expires: new Date(NOW.getTime() + 10 * 60 * 1000),
        attempts: 0,
      },
      update: {
        token: 'hmac:123456',
        expires: new Date(NOW.getTime() + 10 * 60 * 1000),
        attempts: 0,
      },
    });
    expect(result).toEqual({ ok: true, code: '123456' });
  });

  it('returns not-found when no active OTP exists for invalid code', async () => {
    const { consumeVerificationToken } = await import('@/features/auth/server/verify/consumeToken');
    const { prisma } = await import('@/lib/prisma');
    const prismaMock = prisma as unknown as {
      verificationToken: { findFirst: Mock };
      $transaction: Mock;
    };

    prismaMock.$transaction.mockImplementation(async (callback: (tx: {
      verificationToken: { findFirst: Mock };
    }) => Promise<unknown>) =>
      callback({
        verificationToken: { findFirst: vi.fn(async () => null) },
      })
    );
    prismaMock.verificationToken.findFirst.mockResolvedValueOnce(null);

    await expect(consumeVerificationToken('user@example.com', '111111', 'Password1!')).resolves.toEqual({
      ok: false,
      reason: 'not-found',
    });
  });

  it('returns max-attempts after five failed attempts', async () => {
    const { consumeVerificationToken } = await import('@/features/auth/server/verify/consumeToken');
    const { prisma } = await import('@/lib/prisma');
    const prismaMock = prisma as unknown as {
      verificationToken: { findFirst: Mock; update: Mock; deleteMany: Mock };
      $transaction: Mock;
    };

    prismaMock.$transaction.mockImplementation(async (callback: (tx: {
      verificationToken: { findFirst: Mock };
    }) => Promise<unknown>) =>
      callback({
        verificationToken: { findFirst: vi.fn(async () => null) },
      })
    );
    prismaMock.verificationToken.findFirst.mockResolvedValueOnce({
      token: 'hmac:active',
      expires: new Date(NOW.getTime() + 1000),
    });
    prismaMock.verificationToken.update.mockResolvedValue({ attempts: 5 });
    prismaMock.verificationToken.deleteMany.mockResolvedValue({ count: 1 });

    await expect(consumeVerificationToken('user@example.com', '000000', 'Password1!')).resolves.toEqual({
      ok: false,
      reason: 'max-attempts',
    });
  });

  it('marks user verified and deletes all tokens on success', async () => {
    const { consumeVerificationToken } = await import('@/features/auth/server/verify/consumeToken');
    const { prisma } = await import('@/lib/prisma');
    const prismaMock = prisma as unknown as {
      verificationToken: { findFirst: Mock; deleteMany: Mock };
      user: { findUnique: Mock; updateMany: Mock };
      $transaction: Mock;
    };

    prismaMock.$transaction.mockImplementation(async (callback: (tx: {
      user: { findUnique: Mock; updateMany: Mock };
      verificationToken: { findFirst: Mock; deleteMany: Mock };
    }) => Promise<unknown>) =>
      callback({
        user: {
          findUnique: vi.fn(async () => ({ id: 'user-id', emailVerified: null, status: 'INACTIVE' })),
          updateMany: vi.fn(async () => ({ count: 1 })),
        },
        verificationToken: {
          findFirst: vi.fn(async () => ({
            identifier: 'user@example.com',
            token: 'hmac:123456',
            expires: new Date(NOW.getTime() + 1000),
          })),
          deleteMany: vi.fn(async () => ({ count: 1 })),
        },
      })
    );

    await expect(consumeVerificationToken('user@example.com', '123456', 'Password1!')).resolves.toEqual({ ok: true });
    expect(prismaMock.$transaction).toHaveBeenCalledTimes(1);
  });
});

describe('OTP resend flow', () => {
  it('enforces resend cooldown', async () => {
    const { resendVerificationToken } = await import('@/features/auth/server/verify/resend');
    const { prisma } = await import('@/lib/prisma');
    const prismaMock = prisma as unknown as {
      user: { findUnique: Mock };
      verificationToken: { findFirst: Mock };
    };

    prismaMock.user.findUnique.mockResolvedValue({ emailVerified: null, name: null });
    prismaMock.verificationToken.findFirst.mockResolvedValue({
      expires: new Date(NOW.getTime() + 11 * 60 * 1000),
    });

    await expect(resendVerificationToken('cooldown@example.com')).resolves.toEqual({
      ok: false,
      reason: 'cooldown',
    });
  });

  it('creates and emails a new OTP after cooldown', async () => {
    const { resendVerificationToken } = await import('@/features/auth/server/verify/resend');
    const { prisma } = await import('@/lib/prisma');
    const prismaMock = prisma as unknown as {
      user: { findUnique: Mock };
      verificationToken: { findFirst: Mock; upsert: Mock };
      $transaction: Mock;
    };
    const { sendVerificationEmail } = await import('@/features/auth/lib/email/provider');

    prismaMock.user.findUnique.mockResolvedValue({ emailVerified: null, name: 'Ada' });
    prismaMock.verificationToken.findFirst.mockResolvedValue({
      expires: new Date(NOW.getTime() + 5 * 60 * 1000),
    });
    prismaMock.verificationToken.upsert.mockResolvedValue({});

    await expect(resendVerificationToken('User@Example.com')).resolves.toEqual({ ok: true });
    expect(sendVerificationEmail).toHaveBeenCalledWith({
      to: 'user@example.com',
      code: '123456',
      name: 'Ada',
    });
  });
});
