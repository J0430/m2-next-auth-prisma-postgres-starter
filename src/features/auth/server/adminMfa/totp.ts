// RFC 6238 TOTP / RFC 4226 HOTP implemented with node:crypto only (no third-party lib).
// Used to provision and verify admin second factors. Constant-time code comparison.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { base32Decode, base32Encode } from "./base32";

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export type TotpParams = {
  digits: number;
  periodSeconds: number;
  algorithm: TotpAlgorithm;
};

// Authenticator-app defaults (Google Authenticator, 1Password, etc.).
export const DEFAULT_TOTP_PARAMS: TotpParams = {
  digits: 6,
  periodSeconds: 30,
  algorithm: "SHA1",
};

const SECRET_BYTES = 20; // 160-bit secret, standard for SHA1-based TOTP.

// Generate a fresh CSPRNG base32 secret suitable for authenticator enrollment.
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(SECRET_BYTES));
}

function counterToBuffer(counter: number): Buffer {
  const buffer = Buffer.alloc(8);
  // 64-bit big-endian counter; JS numbers are safe for TOTP time ranges.
  buffer.writeBigUInt64BE(BigInt(Math.floor(counter)));
  return buffer;
}

// RFC 4226 HOTP: HMAC + dynamic truncation to `digits` decimal digits.
export function hotp(secretBase32: string, counter: number, params: TotpParams): string {
  const key = Buffer.from(base32Decode(secretBase32));
  const hmac = createHmac(`sha${params.algorithm.slice(3)}`, key)
    .update(counterToBuffer(counter))
    .digest();

  const offsetIndex = hmac.length - 1;
  const offset = (hmac[offsetIndex] ?? 0) & 0x0f;
  const binary =
    (((hmac[offset] ?? 0) & 0x7f) << 24) |
    (((hmac[offset + 1] ?? 0) & 0xff) << 16) |
    (((hmac[offset + 2] ?? 0) & 0xff) << 8) |
    ((hmac[offset + 3] ?? 0) & 0xff);

  return (binary % 10 ** params.digits).toString().padStart(params.digits, "0");
}

// Counter for a given epoch time and period.
export function totpCounter(atMs: number, periodSeconds: number): number {
  return Math.floor(atMs / 1000 / periodSeconds);
}

// RFC 6238 TOTP for a specific instant.
export function totp(secretBase32: string, atMs: number, params: TotpParams = DEFAULT_TOTP_PARAMS): string {
  return hotp(secretBase32, totpCounter(atMs, params.periodSeconds), params);
}

// Verify a submitted code against +/- `window` time steps using constant-time comparison.
export function verifyTotp(
  submittedCode: string,
  secretBase32: string,
  options: { atMs: number; window?: number; params?: TotpParams },
): boolean {
  return matchingTotpStep(submittedCode, secretBase32, options) !== null;
}

// Returns the asserted time step so persistence can consume it atomically.
export function matchingTotpStep(
  submittedCode: string,
  secretBase32: string,
  options: { atMs: number; window?: number; params?: TotpParams },
): number | null {
  const params = options.params ?? DEFAULT_TOTP_PARAMS;
  const window = options.window ?? 1;
  const candidate = submittedCode.trim();
  if (!/^\d+$/u.test(candidate) || candidate.length !== params.digits) {
    return null;
  }

  const baseCounter = totpCounter(options.atMs, params.periodSeconds);
  const submittedBuffer = Buffer.from(candidate, "utf8");

  for (let drift = -window; drift <= window; drift += 1) {
    const expected = hotp(secretBase32, baseCounter + drift, params);
    const expectedBuffer = Buffer.from(expected, "utf8");
    if (
      expectedBuffer.length === submittedBuffer.length &&
      timingSafeEqual(expectedBuffer, submittedBuffer)
    ) {
      return baseCounter + drift;
    }
  }

  return null;
}

// Build the otpauth:// provisioning URI returned ONCE at enrollment (never persisted).
export function buildOtpauthUri(input: {
  secretBase32: string;
  accountName: string;
  issuer: string;
  params?: TotpParams;
}): string {
  const params = input.params ?? DEFAULT_TOTP_PARAMS;
  const label = encodeURIComponent(`${input.issuer}:${input.accountName}`);
  const query = new URLSearchParams({
    secret: input.secretBase32,
    issuer: input.issuer,
    algorithm: params.algorithm,
    digits: String(params.digits),
    period: String(params.periodSeconds),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}
