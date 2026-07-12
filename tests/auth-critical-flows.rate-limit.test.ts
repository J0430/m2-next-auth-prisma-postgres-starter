import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';

const ORIGINAL_ENV = { ...process.env };
const cookieSet = vi.hoisted(() => vi.fn());

vi.mock('@/lib/rateLimit', () => ({
  buildAdmissionRateLimitChecks: vi.fn(() => [
    { scope: 'ip', key: 'rate:limit:key', policy: 'otp-verify-ip' },
  ]),
  buildRateLimitKey: vi.fn(() => 'rate:limit:key'),
  getClientIp: vi.fn(() => '127.0.0.1'),
  rateLimit: vi.fn(),
}));

vi.mock('@/lib/prisma', () => ({
  prisma: {
    user: {
      findUnique: vi.fn(),
      create: vi.fn(),
    },
  },
}));

vi.mock('bcryptjs', () => ({
  default: {
    hash: vi.fn(),
  },
}));

vi.mock('@/features/auth/server/verify/createToken', () => ({
  createVerificationToken: vi.fn(),
}));

vi.mock('@/features/auth/lib/email/provider', () => ({
  sendVerificationEmail: vi.fn(),
}));

vi.mock('next/headers', () => ({
  headers: vi.fn(() => new Headers({ 'x-forwarded-for': '127.0.0.1' })),
  cookies: vi.fn(() => ({
    get: vi.fn(() => undefined),
    set: cookieSet,
  })),
}));

beforeEach(() => {
  vi.resetModules();
  process.env.SKIP_ENV_VALIDATION = 'true';
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://localhost/test';
  process.env.NEXTAUTH_SECRET = process.env.NEXTAUTH_SECRET ?? 'x'.repeat(32);
});

afterEach(() => {
  vi.clearAllMocks();
  Object.keys(process.env).forEach((key) => {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  });
  Object.assign(process.env, ORIGINAL_ENV);
});

describe('Rate-limit enforcement', () => {
  it('fails signup closed before invite admission is present', async () => {
    const { rateLimit } = await import('@/lib/rateLimit');
    const rateLimitMock = rateLimit as unknown as Mock;
    rateLimitMock.mockResolvedValue({
      success: false,
      limit: 3,
      remaining: 0,
      reset: Date.now(),
    });

    const { registerUser } = await import(
      '@/features/auth/server/actions/signup'
    );

    const formData = new FormData();
    formData.set('firstname', 'Test');
    formData.set('lastname', 'User');
    formData.set('email', 'user@example.com');
    formData.set('password', 'MyP@ss123');
    formData.set('repeatpassword', 'MyP@ss123');
    formData.set('country', 'us');
    formData.set('city', 'NYC');
    formData.set('address', '123 Test St');

    await expect(registerUser(formData)).resolves.toEqual({
      ok: false,
      errors: { formErrors: ['Unable to complete this request.'] },
    });
    expect(cookieSet).toHaveBeenCalledWith('registration_session', '', expect.objectContaining({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/register',
      maxAge: 0,
    }));
  });

  it('returns a generic admission response for resend when rate-limited', async () => {
    const { rateLimit } = await import('@/lib/rateLimit');
    const rateLimitMock = rateLimit as unknown as Mock;
    rateLimitMock.mockResolvedValue({
      success: false,
      limit: 3,
      remaining: 0,
      reset: Date.now(),
    });

    const { POST } = await import('@/app/api/auth/verify/resend/route');

    const req = new Request('http://localhost/api/auth/verify/resend', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'user@example.com' }),
    });

    const res = await POST(req);

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({
      ok: false,
      message: 'Unable to complete this request.',
    });
    expect(body.supportId).toMatch(/^admission_/);
    expect(body.reason).toBeUndefined();
  });

  it('throws RATE_LIMITED for credential sign-in', async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    process.env.NEXTAUTH_SECRET = 'x'.repeat(32);

    const rateLimitMock = vi.fn(async () => ({
      success: false,
      limit: 3,
      remaining: 0,
      reset: Date.now(),
    }));

    vi.doMock('@/lib/rateLimit', () => ({
      buildAdmissionRateLimitChecks: vi.fn(() => [
        { scope: 'ip', key: 'login:ip:key', policy: 'login-ip' },
        { scope: 'account', key: 'login:account:key', policy: 'login-account' },
      ]),
      buildRateLimitKey: vi.fn(() => 'rate:limit:key'),
      getClientIp: vi.fn(() => '127.0.0.1'),
      rateLimit: rateLimitMock,
    }));

    const { authOptions } = await import('@/features/auth/server/options');
    const credentialsProvider = authOptions.providers.find(
      (provider) => provider.id === 'credentials'
    ) as any;

    await expect(
      credentialsProvider.options.authorize(
        { email: 'user@example.com', password: 'password123' },
        { headers: {} }
      )
    ).rejects.toThrow('RATE_LIMITED');

    expect(rateLimitMock).toHaveBeenCalled();
  });
});
