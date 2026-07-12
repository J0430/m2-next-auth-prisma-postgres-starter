// Authenticated encryption for admin TOTP secrets at rest (AES-256-GCM).
// Writes use ADMIN_MFA_SECRET_KEY_VERSION; decryption selects the key by the row's
// stored keyVersion from ADMIN_MFA_SECRET_ENCRYPTION_KEYS. Unknown version => fail closed.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { env } from "@/lib/env";

const AES_GCM_ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_HEX_PATTERN = /^[a-f0-9]{64}$/i;

export type EncryptedTotpSecret = {
  cipher: Uint8Array;
  keyVersion: number;
};

function parseKey(keyHex: string): Buffer {
  if (!KEY_HEX_PATTERN.test(keyHex)) {
    throw new Error("ADMIN_MFA_SECRET_KEY_INVALID");
  }
  return Buffer.from(keyHex, "hex");
}

// Resolve the hex key for a numeric version from the env keyring, or fail closed.
function keyForVersion(version: number): Buffer {
  const keyring = env.ADMIN_MFA_SECRET_ENCRYPTION_KEYS;
  if (!keyring) throw new Error("ADMIN_MFA_SECRET_KEYRING_MISSING");
  const keyHex = keyring[String(version)];
  if (!keyHex) throw new Error("ADMIN_MFA_SECRET_KEY_VERSION_UNKNOWN");
  return parseKey(keyHex);
}

// Resolve the active write-version (integer) from env, or fail closed.
function activeWriteVersion(): number {
  const raw = env.ADMIN_MFA_SECRET_KEY_VERSION;
  if (!raw) throw new Error("ADMIN_MFA_SECRET_KEY_VERSION_MISSING");
  const version = Number(raw);
  if (!Number.isInteger(version)) throw new Error("ADMIN_MFA_SECRET_KEY_VERSION_INVALID");
  return version;
}

// Encrypt a plaintext TOTP secret with the current write-version key.
export function encryptTotpSecret(plaintextSecret: string): EncryptedTotpSecret {
  const keyVersion = activeWriteVersion();
  const key = keyForVersion(keyVersion);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(AES_GCM_ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintextSecret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { cipher: Buffer.concat([iv, tag, ciphertext]), keyVersion };
}

// Decrypt using the key selected by the row's stored keyVersion. Fails closed on any error
// (unknown version, tampered ciphertext, wrong key) so callers can deny generically.
export function decryptTotpSecret(cipher: Uint8Array, keyVersion: number): string {
  try {
    const key = keyForVersion(keyVersion);
    const bytes = Buffer.from(cipher);
    if (bytes.length <= IV_BYTES + TAG_BYTES) throw new Error("ADMIN_MFA_SECRET_DECRYPT_FAILED");

    const iv = bytes.subarray(0, IV_BYTES);
    const tag = bytes.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const encrypted = bytes.subarray(IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv(AES_GCM_ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("ADMIN_MFA_SECRET_DECRYPT_FAILED");
  }
}

type AdminMfaKeyVersionReader = {
  adminMfaFactor: {
    findMany(input: { distinct: ["keyVersion"]; select: { keyVersion: true } }): Promise<Array<{ keyVersion: number }>>;
  };
};

// Explicit startup/readiness check; importing this module never performs database I/O.
export async function validateStoredAdminMfaKeyVersions(reader: AdminMfaKeyVersionReader): Promise<void> {
  const versions = await reader.adminMfaFactor.findMany({ distinct: ["keyVersion"], select: { keyVersion: true } });
  for (const { keyVersion } of versions) keyForVersion(keyVersion);
}
