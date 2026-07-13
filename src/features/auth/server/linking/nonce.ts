// CSPRNG nonce generation and hash-only, timing-safe comparison for link intents.
// Mirrors the invites/token.ts hash-only storage precedent.
import crypto from "node:crypto";

const LINK_NONCE_BYTES = 32;

// Decoy digest keeps the comparison running when no stored hash exists.
const DECOY_LINK_NONCE_HASH = crypto
  .createHash("sha256")
  .update("manumu:account-link-decoy")
  .digest();

export function generateLinkNonce(): string {
  return crypto.randomBytes(LINK_NONCE_BYTES).toString("base64url");
}

export function hashLinkNonce(rawNonce: string): Buffer {
  return crypto.createHash("sha256").update(rawNonce).digest();
}

export function constantTimeNonceHashMatches(
  candidateHash: Buffer,
  storedHash: Buffer | Uint8Array | null,
): boolean {
  const comparableHash = storedHash ? Buffer.from(storedHash) : DECOY_LINK_NONCE_HASH;
  return crypto.timingSafeEqual(candidateHash, comparableHash);
}
